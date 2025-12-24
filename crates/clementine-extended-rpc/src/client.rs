//! Extended Bitcoin RPC client with retry logic.

use async_trait::async_trait;
use bitcoin::{Amount, FeeRate, Network, OutPoint, TxOut, Txid};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use clementine_errors::{BitcoinRPCError, FeeErr};
use eyre::{eyre, Context, OptionExt};
use http::StatusCode;
use secrecy::{ExposeSecret, SecretString};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use tokio_retry::RetryIf;

pub use crate::retry::{RetryConfig, RetryableError};

#[cfg(any(test, feature = "test-utils"))]
use bitcoin::Address;
use tokio::sync::RwLock;

/// Result type for RPC operations.
type Result<T> = std::result::Result<T, BitcoinRPCError>;

/// Bitcoin RPC wrapper with retry logic.
///
/// Provides useful wrapper functions for common operations, as well as
/// direct access to Bitcoin RPC through the `RpcApi` trait.
#[derive(Clone)]
pub struct ExtendedBitcoinRpc {
    url: String,
    client: Arc<Client>,
    retry_config: RetryConfig,

    #[cfg(any(test, feature = "test-utils"))]
    cached_mining_address: Arc<RwLock<Option<String>>>,
}

impl std::fmt::Debug for ExtendedBitcoinRpc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtendedBitcoinRpc")
            .field("url", &self.url)
            .finish()
    }
}

impl ExtendedBitcoinRpc {
    /// Connects to Bitcoin RPC server with built-in retry mechanism.
    ///
    /// This method attempts to connect to the Bitcoin RPC server and creates a new
    /// [`ExtendedBitcoinRpc`] instance. It includes retry logic that will retry
    /// connection attempts for retryable errors using exponential backoff.
    ///
    /// # Parameters
    ///
    /// * `url` - The RPC server URL
    /// * `user` - Username for RPC authentication
    /// * `password` - Password for RPC authentication
    /// * `retry_config` - Optional retry configuration. If None, uses default config.
    ///
    /// # Returns
    ///
    /// - [`Result<ExtendedBitcoinRpc>`]: A new ExtendedBitcoinRpc instance on success
    ///
    /// # Errors
    ///
    /// - [`BitcoinRPCError`]: If connection fails after all retry attempts or ping fails
    pub async fn connect(
        url: String,
        user: SecretString,
        password: SecretString,
        retry_config: Option<RetryConfig>,
    ) -> Result<Self> {
        let config = retry_config.clone().unwrap_or_default();

        let url_clone = url.clone();
        let user_clone = user.clone();
        let password_clone = password.clone();

        let retry_strategy = config.get_strategy();

        RetryIf::spawn(
            retry_strategy,
            || async {
                let auth = Auth::UserPass(
                    user_clone.expose_secret().to_string(),
                    password_clone.expose_secret().to_string(),
                );

                let retry_config = retry_config.clone().unwrap_or_default();

                tracing::debug!(
                    "Attempting to connect to Bitcoin RPC at {} with retry config: {:?}",
                    &url_clone,
                    &retry_config
                );
                let rpc = Client::new(&url_clone, auth)
                    .await
                    .wrap_err("Failed to connect to Bitcoin RPC")?;

                // Ping to ensure connection works
                tracing::debug!(
                    "Pinging Bitcoin RPC at {} to make sure it's alive",
                    &url_clone
                );
                rpc.ping()
                    .await
                    .map_err(|e| eyre::eyre!("Failed to ping Bitcoin RPC: {}", e))?;

                let result: Result<ExtendedBitcoinRpc> = Ok(Self {
                    url: url_clone.clone(),
                    client: Arc::new(rpc),
                    retry_config,
                    #[cfg(any(test, feature = "test-utils"))]
                    cached_mining_address: Arc::new(RwLock::new(None)),
                });

                match &result {
                    Ok(_) => tracing::debug!("Connected to Bitcoin RPC successfully"),
                    Err(error) => {
                        if !error.is_retryable() {
                            tracing::debug!("Non-retryable connection error: {}", error);
                        } else {
                            tracing::debug!("Bitcoin RPC connection failed, will retry: {}", error);
                        }
                    }
                }

                result
            },
            |error: &BitcoinRPCError| error.is_retryable(),
        )
        .await
    }

    /// Returns the URL of the RPC server.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Returns a reference to the retry configuration.
    pub fn retry_config(&self) -> &RetryConfig {
        &self.retry_config
    }

    /// Returns a reference to the inner client.
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Generates a new Bitcoin address for the wallet.
    pub async fn get_new_wallet_address(&self) -> Result<Address> {
        self.get_new_address(None, None)
            .await
            .wrap_err("Failed to get new address")
            .map(|addr| addr.assume_checked())
            .map_err(Into::into)
    }
    /// Returns the number of confirmations for a transaction.
    ///
    /// # Parameters
    ///
    /// * `txid`: TXID of the transaction to check.
    ///
    /// # Returns
    ///
    /// - [`u32`]: The number of confirmations for the transaction.
    ///
    /// # Errors
    ///
    /// - [`BitcoinRPCError`]: If the transaction is not confirmed (0) or if
    ///   there was an error retrieving the transaction info.
    pub async fn confirmation_blocks(&self, txid: &bitcoin::Txid) -> Result<u32> {
        let raw_tx_res = self
            .get_raw_transaction_info(txid, None)
            .await
            .wrap_err("Failed to get transaction info")?;
        raw_tx_res
            .confirmations
            .ok_or_else(|| eyre::eyre!("No confirmation data for transaction {}", txid))
            .map_err(Into::into)
    }

    /// Retrieves the current blockchain height (number of blocks).
    ///
    /// # Returns
    ///
    /// - [`u32`]: Current block height
    pub async fn get_current_chain_height(&self) -> Result<u32> {
        let height = self
            .get_block_count()
            .await
            .wrap_err("Failed to get current chain height")?;
        Ok(u32::try_from(height).wrap_err("Failed to convert block count to u32")?)
    }

    /// Returns block hash of a transaction, if confirmed.
    ///
    /// # Parameters
    ///
    /// * `txid`: TXID of the transaction to check.
    ///
    /// # Returns
    ///
    /// - [`bitcoin::BlockHash`]: Block hash of the block that the transaction
    ///   is in.
    ///
    /// # Errors
    ///
    /// - [`BitcoinRPCError`]: If the transaction is not confirmed (0) or if
    ///   there was an error retrieving the transaction info.
    pub async fn get_blockhash_of_tx(&self, txid: &bitcoin::Txid) -> Result<bitcoin::BlockHash> {
        let raw_transaction_results = self
            .get_raw_transaction_info(txid, None)
            .await
            .wrap_err("Failed to get transaction info")?;
        let Some(blockhash) = raw_transaction_results.blockhash else {
            return Err(eyre::eyre!("Transaction not confirmed: {0}", txid).into());
        };
        Ok(blockhash)
    }

    /// Retrieves the block header and hash for a given block height.
    ///
    /// # Arguments
    ///
    /// * `height`: Target block height.
    ///
    /// # Returns
    ///
    /// - ([`bitcoin::BlockHash`], [`bitcoin::block::Header`]): A tuple
    ///   containing the block hash and header.
    pub async fn get_block_info_by_height(
        &self,
        height: u64,
    ) -> Result<(bitcoin::BlockHash, bitcoin::block::Header)> {
        let block_hash = self.get_block_hash(height).await.wrap_err(format!(
            "Couldn't retrieve block hash from height {height} from rpc"
        ))?;
        let block_header = self.get_block_header(&block_hash).await.wrap_err(format!(
            "Couldn't retrieve block header with block hash {block_hash} from rpc"
        ))?;

        Ok((block_hash, block_header))
    }

    /// Gets the transactions that created the inputs of a given transaction.
    ///
    /// # Arguments
    ///
    /// * `tx` - The transaction to get the previous transactions for
    ///
    /// # Returns
    ///
    /// A vector of transactions that created the inputs of the given transaction.
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_prevout_txs(
        &self,
        tx: &bitcoin::Transaction,
    ) -> Result<Vec<bitcoin::Transaction>> {
        let mut prevout_txs = Vec::new();
        for input in &tx.input {
            let txid = input.previous_output.txid;
            prevout_txs.push(self.get_tx_of_txid(&txid).await?);
        }
        Ok(prevout_txs)
    }

    /// Gets the transaction data for a given transaction ID.
    ///
    /// # Parameters
    ///
    /// * `txid`: TXID of the transaction to check.
    ///
    /// # Returns
    ///
    /// - [`bitcoin::Transaction`]: Transaction itself.
    pub async fn get_tx_of_txid(&self, txid: &bitcoin::Txid) -> Result<bitcoin::Transaction> {
        let raw_transaction = self
            .get_raw_transaction(txid, None)
            .await
            .wrap_err("Failed to get raw transaction")?;
        Ok(raw_transaction)
    }

    /// Checks if a transaction is on-chain.
    ///
    /// # Parameters
    ///
    /// * `txid`: TXID of the transaction to check.
    ///
    /// # Returns
    ///
    /// - [`bool`]: `true` if the transaction is on-chain, `false` otherwise.
    pub async fn is_tx_on_chain(&self, txid: &bitcoin::Txid) -> Result<bool> {
        Ok(self
            .get_raw_transaction_info(txid, None)
            .await
            .ok()
            .and_then(|s| s.blockhash)
            .is_some())
    }

    /// Checks if a transaction UTXO has expected address and amount.
    ///
    /// # Parameters
    ///
    /// * `outpoint` - The outpoint to check
    /// * `address` - Expected script pubkey
    /// * `amount_sats` - Expected amount in satoshis
    ///
    /// # Returns
    ///
    /// - [`bool`]: `true` if the UTXO has the expected address and amount, `false` otherwise.
    pub async fn check_utxo_address_and_amount(
        &self,
        outpoint: &OutPoint,
        address: &bitcoin::ScriptBuf,
        amount_sats: Amount,
    ) -> Result<bool> {
        let tx = self
            .get_raw_transaction(&outpoint.txid, None)
            .await
            .wrap_err("Failed to get transaction")?;

        let current_output = tx
            .output
            .get(outpoint.vout as usize)
            .ok_or(eyre!(
                "No output at index {} for txid {}",
                outpoint.vout,
                outpoint.txid
            ))?
            .to_owned();

        let expected_output = TxOut {
            script_pubkey: address.clone(),
            value: amount_sats,
        };

        Ok(expected_output == current_output)
    }

    /// Checks if an UTXO is spent.
    ///
    /// # Parameters
    ///
    /// * `outpoint`: The outpoint to check
    ///
    /// # Returns
    ///
    /// - [`bool`]: `true` if the UTXO is spent, `false` otherwise.
    ///
    /// # Errors
    ///
    /// - [`BitcoinRPCError`]: If the transaction is not confirmed or if there
    ///   was an error retrieving the transaction output.
    pub async fn is_utxo_spent(&self, outpoint: &OutPoint) -> Result<bool> {
        if !self.is_tx_on_chain(&outpoint.txid).await? {
            return Err(BitcoinRPCError::TransactionNotConfirmed);
        }

        let res = self
            .get_tx_out(&outpoint.txid, outpoint.vout, Some(false))
            .await
            .wrap_err("Failed to get transaction output")?;

        Ok(res.is_none())
    }

    /// Attempts to mine the specified number of blocks and returns their hashes.
    ///
    /// This test-only async function will mine `block_num` blocks on the Bitcoin regtest network
    /// using a cached mining address or a newly generated one. It retries up to 5 times on failure
    /// with exponential backoff.
    ///
    /// # Parameters
    /// - `block_num`: The number of blocks to mine.
    ///
    /// # Returns
    /// - `Ok(Vec<BlockHash>)`: A vector of block hashes for the mined blocks.
    /// - `Err`: If mining fails after all retry attempts.
    #[cfg(any(test, feature = "test-utils"))]
    pub async fn mine_blocks(&self, block_num: u64) -> Result<Vec<bitcoin::BlockHash>> {
        if block_num == 0 {
            return Ok(vec![]);
        }

        self.try_mine(block_num).await
    }

    /// Internal helper that performs the actual block mining logic.
    ///
    /// It uses a cached mining address if available, otherwise it generates and caches
    /// a new one. It then uses the address to mine `block_num` blocks.
    ///
    /// # Parameters
    /// - `block_num`: The number of blocks to mine.
    ///
    /// # Returns
    /// - `Ok(Vec<BlockHash>)`: The list of block hashes.
    /// - `Err`: If the client fails to get a new address or mine the blocks.
    #[cfg(any(test, feature = "test-utils"))]
    async fn try_mine(&self, block_num: u64) -> Result<Vec<bitcoin::BlockHash>> {
        let address = {
            let read = self.cached_mining_address.read().await;
            if let Some(addr) = &*read {
                addr.clone()
            } else {
                drop(read);
                let mut write = self.cached_mining_address.write().await;

                if let Some(addr) = &*write {
                    addr.clone()
                } else {
                    let new_addr = self
                        .get_new_address(None, None)
                        .await
                        .wrap_err("Failed to get new address")?
                        .assume_checked()
                        .to_string();
                    *write = Some(new_addr.clone());
                    new_addr
                }
            }
        };

        let address = Address::from_str(&address)
            .wrap_err("Invalid address format")?
            .assume_checked();
        let blocks = self
            .generate_to_address(block_num, &address)
            .await
            .wrap_err("Failed to generate to address")?;

        Ok(blocks)
    }

    /// Gets the number of transactions in the mempool.
    ///
    /// # Returns
    ///
    /// - [`usize`]: The number of transactions in the mempool.
    pub async fn mempool_size(&self) -> Result<usize> {
        let mempool_info = self
            .get_mempool_info()
            .await
            .wrap_err("Failed to get mempool info")?;
        Ok(mempool_info.size)
    }

    /// Sends a specified amount of Bitcoins to the given address.
    ///
    /// # Parameters
    ///
    /// * `address` - The recipient address
    /// * `amount_sats` - The amount to send in satoshis
    ///
    /// # Returns
    ///
    /// - [`OutPoint`]: The outpoint (txid and vout) of the newly created output.
    pub async fn send_to_address(
        &self,
        address: &Address,
        amount_sats: Amount,
    ) -> Result<OutPoint> {
        let txid = self
            .client
            .send_to_address(
                address,
                amount_sats,
                None,
                None,
                None,
                Some(true),
                Some(2),
                Some(bitcoincore_rpc::json::EstimateMode::Conservative),
            )
            .await
            .wrap_err("Failed to send to address")?;

        let tx_result = self
            .get_transaction(&txid, None)
            .await
            .wrap_err("Failed to get transaction")?;
        let vout = tx_result.details[0].vout;

        Ok(OutPoint { txid, vout })
    }

    /// Retrieves the transaction output for a given outpoint.
    ///
    /// # Arguments
    ///
    /// * `outpoint` - The outpoint (txid and vout) to retrieve
    ///
    /// # Returns
    ///
    /// - [`TxOut`]: The transaction output at the specified outpoint.
    pub async fn get_txout_from_outpoint(&self, outpoint: &OutPoint) -> Result<TxOut> {
        let tx = self
            .get_raw_transaction(&outpoint.txid, None)
            .await
            .wrap_err("Failed to get transaction")?;
        let txout = tx
            .output
            .get(outpoint.vout as usize)
            .ok_or(eyre!(
                "No output at index {} for txid {}",
                outpoint.vout,
                outpoint.txid
            ))?
            .to_owned();

        Ok(txout)
    }

    /// Bumps the fee of a transaction to meet or exceed a target fee rate. Does
    /// nothing if the transaction is already confirmed. Returns the original
    /// txid if no bump was needed.
    ///
    /// This function implements Replace-By-Fee (RBF) to increase the fee of an unconfirmed transaction.
    /// It works as follows:
    /// 1. If the transaction is already confirmed, returns Err(TransactionAlreadyInBlock)
    /// 2. If the current fee rate is already >= the requested fee rate, returns the original txid
    /// 3. Otherwise, increases the fee rate by adding the node's incremental fee to the current fee rate, then `bump_fee`s the transaction
    ///
    /// Note: This function currently only supports fee payer TXs.
    ///
    /// # Arguments
    /// * `txid` - The transaction ID to bump
    /// * `fee_rate` - The target fee rate to achieve
    ///
    /// # Returns
    ///
    /// - [`Txid`]: The txid of the bumped transaction (which may be the same as the input txid if no bump was needed).
    ///
    /// # Errors
    ///
    ///  * `TransactionAlreadyInBlock` - If the transaction is already confirmed
    /// * `BumpFeeUTXOSpent` - If the UTXO being spent by the transaction is already spent
    /// * `BumpFeeError` - For other errors with fee bumping
    pub async fn bump_fee_with_fee_rate(&self, txid: Txid, fee_rate: FeeRate) -> Result<Txid> {
        // Check if transaction is already confirmed
        let transaction_info = self
            .get_transaction(&txid, None)
            .await
            .wrap_err("Failed to get transaction")?;
        if transaction_info.info.blockhash.is_some() {
            return Err(BitcoinRPCError::TransactionAlreadyInBlock(
                transaction_info
                    .info
                    .blockhash
                    .expect("Blockhash should be present"),
            ));
        }

        // Calculate current fee rate
        let tx = transaction_info
            .transaction()
            .wrap_err("Failed to get transaction")?;
        let tx_weight = tx.weight().to_wu();
        let current_fee_sat = u64::try_from(
            transaction_info
                .fee
                .expect("Fee should be present")
                .to_sat()
                .abs(),
        )
        .wrap_err("Failed to convert fee to sat")?;

        let current_fee_rate_sat_kwu = current_fee_sat as f64 * 1000.0 / tx_weight as f64;

        tracing::trace!(
            "Bump fee with fee rate txid: {txid} - Current fee sat: {current_fee_sat} - current fee rate: {current_fee_rate_sat_kwu}"
        );

        // If current fee rate is already sufficient, return original txid
        if current_fee_rate_sat_kwu >= fee_rate.to_sat_per_kwu() as f64 {
            return Ok(txid);
        }

        tracing::trace!(
            "Bump fee with fee rate txid: {txid} - Current fee rate: {current_fee_rate_sat_kwu} sat/kwu, target fee rate: {fee_rate} sat/kwu"
        );

        // Get node's incremental fee to determine how much to increase
        let network_info = self
            .get_network_info()
            .await
            .wrap_err("Failed to get network info")?;
        // incremental fee is in BTC/kvB
        let incremental_fee = network_info.incremental_fee;
        // Convert from sat/kvB to sat/kwu by dividing by 4.0, since 1 kvB = 4 kwu.
        let incremental_fee_rate_sat_kwu = incremental_fee.to_sat() as f64 / 4.0;

        // Calculate new fee rate by adding incremental fee to current fee rate, or use the target fee rate if it's higher
        let new_fee_rate = FeeRate::from_sat_per_kwu(std::cmp::max(
            (current_fee_rate_sat_kwu + incremental_fee_rate_sat_kwu).ceil() as u64,
            fee_rate.to_sat_per_kwu(),
        ));

        tracing::debug!(
            "Bumping fee for txid: {txid} from {current_fee_rate_sat_kwu} to {new_fee_rate} with incremental fee {incremental_fee_rate_sat_kwu} - Final fee rate: {new_fee_rate}, current chain fee rate: {fee_rate}"
        );

        // Call Bitcoin Core's bumpfee RPC
        let bump_fee_result = match self
            .bump_fee(
                &txid,
                Some(&bitcoincore_rpc::json::BumpFeeOptions {
                    fee_rate: Some(bitcoincore_rpc::json::FeeRate::per_vbyte(Amount::from_sat(
                        new_fee_rate.to_sat_per_vb_ceil(),
                    ))),
                    replaceable: Some(true),
                    ..Default::default()
                }),
            )
            .await
        {
            Ok(bump_fee_result) => bump_fee_result,
            // Attempt to parse the error message to get the outpoint if the UTXO is already spent
            Err(e) => match e {
                bitcoincore_rpc::Error::JsonRpc(json_rpc_error) => match json_rpc_error {
                    bitcoincore_rpc::RpcError::Rpc(rpc_error) => {
                        if let Some((outpoint_str, _)) =
                            rpc_error.message.split_once(" is already spent")
                        {
                            let outpoint = OutPoint::from_str(outpoint_str)
                                .wrap_err(BitcoinRPCError::BumpFeeError(txid, fee_rate))?;

                            return Err(BitcoinRPCError::BumpFeeUTXOSpent(outpoint));
                        }

                        return Err(eyre::eyre!("{:?}", rpc_error)
                            .wrap_err(BitcoinRPCError::BumpFeeError(txid, fee_rate))
                            .into());
                    }
                    _ => {
                        return Err(eyre::eyre!(json_rpc_error)
                            .wrap_err(BitcoinRPCError::BumpFeeError(txid, fee_rate))
                            .into());
                    }
                },
                _ => {
                    return Err(eyre::eyre!(e)
                        .wrap_err(BitcoinRPCError::BumpFeeError(txid, fee_rate))
                        .into())
                }
            },
        };

        Ok(bump_fee_result
            .txid
            .ok_or_eyre("Failed to get Txid from bump_fee_result")?)
    }

    /// Creates a new instance of the [`ExtendedBitcoinRpc`] with a new client
    /// connection for cloning. This is needed when you need a separate
    /// connection to the Bitcoin RPC server.
    ///
    /// # Returns
    ///
    /// - [`ExtendedBitcoinRpc`]: A new instance of ExtendedBitcoinRpc with a new client connection.
    pub async fn clone_inner(&self) -> std::result::Result<Self, bitcoincore_rpc::Error> {
        Ok(Self {
            url: self.url.clone(),
            client: self.client.clone(),
            retry_config: self.retry_config.clone(),
            #[cfg(any(test, feature = "test-utils"))]
            cached_mining_address: self.cached_mining_address.clone(),
        })
    }

    /// Retrieves the block for a given height.
    ///
    /// # Arguments
    ///
    /// * `height` - The target block height.
    ///
    /// # Returns
    ///
    /// - [`bitcoin::Block`]: The block at the specified height.
    pub async fn get_block_by_height(&self, height: u64) -> Result<bitcoin::Block> {
        let hash = self
            .get_block_info_by_height(height)
            .await
            .wrap_err("Failed to get block info by height")?
            .0;

        Ok(self
            .get_block(&hash)
            .await
            .wrap_err("Failed to get block by height")?)
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
    pub async fn get_fee_rate(
        &self,
        network: Network,
        mempool_api_host: &Option<String>,
        mempool_api_endpoint: &Option<String>,
        mempool_fee_rate_multiplier: u64,
        mempool_fee_rate_offset_sat_kvb: u64,
        fee_rate_hard_cap: u64,
    ) -> Result<FeeRate> {
        match network {
            // Regtest use a fixed, low fee rate.
            Network::Regtest => {
                tracing::debug!("Using fixed fee rate of 1 sat/vB for {network} network");
                Ok(FeeRate::from_sat_per_vb_unchecked(1))
            }

            // Mainnet and Testnet4 fetch fees from Mempool Space and Bitcoin Core RPC.
            Network::Bitcoin | Network::Testnet4 | Network::Signet => {
                tracing::debug!("Fetching fee rate for {network} network...");

                // Fetch fees from both mempool.space and Bitcoin Core RPC
                let mempool_fee = get_fee_rate_from_mempool_space(
                    mempool_api_host,
                    mempool_api_endpoint,
                    network,
                )
                .await;

                let rpc_fee = timeout(Duration::from_secs(30), self.estimate_smart_fee(1, None))
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
                        let multiplier = mempool_fee_rate_multiplier;
                        let offset = mempool_fee_rate_offset_sat_kvb;
                        let rpc_amt_sat = rpc_amt.to_sat();

                        let threshold_sat = multiplier
                            .checked_mul(rpc_amt_sat)
                            .and_then(|v| v.checked_add(offset))
                            .ok_or_else(|| {
                                eyre!("Overflow when calculating threshold_sat in fee selection ({multiplier} * {rpc_amt_sat} + {offset})")
                            })?;

                        let threshold = Amount::from_sat(threshold_sat);

                        if mempool_amt <= threshold {
                            tracing::debug!(
                                "Selected mempool.space fee rate: {} sat/kvB (mempool: {}, rpc: {}, threshold: {})",
                                mempool_amt.to_sat(),
                                mempool_amt.to_sat(),
                                rpc_amt.to_sat(),
                                threshold
                            );
                            mempool_amt
                        } else {
                            tracing::debug!(
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
                if fee_sat_kvb > fee_rate_hard_cap * 1000 {
                    tracing::warn!(
                        "Fee rate {} sat/kvb exceeds hard cap {} sat/kvb, using hard cap",
                        fee_sat_kvb,
                        fee_rate_hard_cap * 1000
                    );
                    fee_sat_kvb = fee_rate_hard_cap * 1000;
                }

                tracing::debug!("Final fee rate: {} sat/kvb", fee_sat_kvb);
                Ok(FeeRate::from_sat_per_kwu(fee_sat_kvb.div_ceil(4)))
            }

            // All other network types are unsupported.
            _ => Err(eyre!(
                "Fee rate estimation is not supported for network: {:?}",
                network
            )
            .into()),
        }
    }
}

/// Fetches the current recommended fee rate from the provider. Currently only supports
/// Mempool Space API.
/// This function is used to get the fee rate in sat/vkb (satoshis per kilovbyte).
/// See [Mempool Space API](https://mempool.space/docs/api/rest#get-recommended-fees) for more details.
pub async fn get_fee_rate_from_mempool_space(
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
        Network::Bitcoin => format!("{url}{endpoint}"),
        // If the variables are not, return Error to fallback to Bitcoin Core RPC.
        Network::Testnet4 => format!("{url}testnet4/{endpoint}"),
        Network::Signet => {
            tracing::warn!("You should use Citrea signet url for mempool.space");
            format!("{url}{endpoint}")
        }
        _ => return Err(eyre!("Unsupported network for mempool.space: {network:?}").into()),
    };

    let retry_config = RetryConfig::new(250, Duration::from_secs(5), 4, 2, true);
    let retry_strategy = retry_config.get_strategy();

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
    .wrap_err_with(|| format!("Failed to fetch/parse fees from {url}"))?;

    // The API returns the fee rate in sat/vB. We multiply by 1000 to get sat/kvB.
    Ok(Amount::from_sat(fee_sat_per_vb * 1000))
}

#[async_trait]
/// Implementation of RpcApi with retry logic for all calls.
impl RpcApi for ExtendedBitcoinRpc {
    async fn call<T: for<'a> serde::de::Deserialize<'a>>(
        &self,
        cmd: &str,
        args: &[serde_json::Value],
    ) -> std::result::Result<T, bitcoincore_rpc::Error> {
        tracing::trace!("Calling Bitcoin RPC command: {}", cmd);
        let strategy = self.retry_config.get_strategy();

        let condition = |error: &bitcoincore_rpc::Error| error.is_retryable();

        RetryIf::spawn(
            strategy,
            || async { self.client.call(cmd, args).await },
            condition,
        )
        .await
    }
}
