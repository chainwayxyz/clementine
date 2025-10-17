//! # Bitcoin Extended RPC Interface
//!
//! Extended RPC interface communicates with the Bitcoin node. It features some
//! common wrappers around typical RPC operations as well as direct
//! communication interface with the Bitcoin node.
//!
//! ## Tests
//!
//! In tests, Bitcoind node and client are usually created using
//! [`crate::test::common::create_regtest_rpc`]. Please refer to
//! [`crate::test::common`] for using [`ExtendedBitcoinRpc`] in tests.

use async_trait::async_trait;
use bitcoin::Address;
use bitcoin::Amount;
use bitcoin::BlockHash;
use bitcoin::FeeRate;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::TxOut;
use bitcoin::Txid;
use bitcoincore_rpc::Auth;
use bitcoincore_rpc::Client;
use bitcoincore_rpc::RpcApi;
use eyre::eyre;
use eyre::Context;
use eyre::OptionExt;
use secrecy::ExposeSecret;
use secrecy::SecretString;
use std::iter::Take;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::RetryIf;

use crate::builder::address::create_taproot_address;
use crate::builder::transaction::create_round_txhandlers;
use crate::builder::transaction::input::UtxoVout;
use crate::builder::transaction::KickoffWinternitzKeys;
use crate::builder::transaction::TransactionType;
use crate::builder::transaction::TxHandler;
use crate::config::protocol::ProtocolParamset;
use crate::deposit::OperatorData;
use crate::errors::BridgeError;
use crate::operator::RoundIndex;

#[cfg(test)]
use crate::{
    citrea::CitreaClientT,
    test::common::{are_all_state_managers_synced, test_actors::TestActors},
};

type Result<T> = std::result::Result<T, BitcoinRPCError>;

const MAX_RETRY_ATTEMPTS: usize = 50;

#[derive(Clone)]
pub struct RetryConfig {
    pub initial_delay_millis: u64,
    pub max_delay: Duration,
    pub max_attempts: usize,
    pub backoff_multiplier: u64,
    pub is_jitter: bool,
    // Store the base iterator configuration
    base_strategy: Arc<Take<ExponentialBackoff>>,
}

impl RetryConfig {
    pub fn new(
        initial_delay_millis: u64,
        max_delay: Duration,
        max_attempts: usize,
        backoff_multiplier: u64,
        is_jitter: bool,
    ) -> Self {
        // The crate use is confusing. ExponentialBackoff::from_millis defines the base,
        // given the backoff_multiplier (this is supposed to be the initial delay), the
        // starting factor becomes backoff_multiplier / initial_delay_millis.
        let base: u64 = initial_delay_millis / backoff_multiplier;

        let max_attempts = std::cmp::min(max_attempts, MAX_RETRY_ATTEMPTS);

        // Create the base strategy once
        let base_strategy = Arc::new(
            ExponentialBackoff::from_millis(backoff_multiplier)
                .max_delay(max_delay)
                .factor(base)
                .take(max_attempts),
        );

        Self {
            initial_delay_millis,
            max_delay,
            max_attempts,
            backoff_multiplier,
            is_jitter,
            base_strategy,
        }
    }

    pub fn get_strategy(&self) -> Box<dyn Iterator<Item = Duration> + Send> {
        // Clone the base strategy to get a fresh iterator with the same initial state
        let base_strategy = (*self.base_strategy).clone();

        if self.is_jitter {
            Box::new(base_strategy.map(jitter))
        } else {
            Box::new(base_strategy)
        }
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self::new(100, Duration::from_secs(30), 5, 2, false)
    }
}

impl std::fmt::Debug for RetryConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetryConfig")
            .field("initial_delay_millis", &self.initial_delay_millis)
            .field("max_delay", &self.max_delay)
            .field("max_attempts", &self.max_attempts)
            .field("backoff_multiplier", &self.backoff_multiplier)
            .field("is_jitter", &self.is_jitter)
            .finish()
    }
}

/// Trait to determine if an error is retryable
pub trait RetryableError {
    fn is_retryable(&self) -> bool;
}

impl RetryableError for bitcoincore_rpc::Error {
    fn is_retryable(&self) -> bool {
        tracing::trace!("Checking if error is retryable: {:?}", self);
        let result = match self {
            // JSON-RPC errors - check specific error patterns
            bitcoincore_rpc::Error::JsonRpc(jsonrpc_error) => {
                let error_str = jsonrpc_error.to_string().to_lowercase();
                tracing::trace!("JsonRpc error string (lowercase): {}", error_str);
                // Retry on connection issues, timeouts, temporary failures
                let is_retryable = error_str.contains("timeout")
                    || error_str.contains("connection")
                    || error_str.contains("temporary")
                    || error_str.contains("busy")
                    || error_str.contains("unavailable")
                    || error_str.contains("network")
                    || error_str.contains("broken pipe")
                    || error_str.contains("connection reset")
                    || error_str.contains("connection refused")
                    || error_str.contains("host unreachable");
                tracing::trace!("JsonRpc error is_retryable: {}", is_retryable);
                is_retryable
            }

            // I/O errors are typically network-related and retryable
            bitcoincore_rpc::Error::Io(io_error) => {
                use std::io::ErrorKind;
                match io_error.kind() {
                    // These are typically temporary network issues
                    ErrorKind::ConnectionRefused
                    | ErrorKind::ConnectionReset
                    | ErrorKind::ConnectionAborted
                    | ErrorKind::NotConnected
                    | ErrorKind::BrokenPipe
                    | ErrorKind::TimedOut
                    | ErrorKind::Interrupted
                    | ErrorKind::UnexpectedEof => true,

                    // These are typically permanent issues
                    ErrorKind::PermissionDenied
                    | ErrorKind::NotFound
                    | ErrorKind::InvalidInput
                    | ErrorKind::InvalidData => false,

                    // For other kinds, be conservative and retry
                    _ => true,
                }
            }

            // Authentication errors are typically permanent
            bitcoincore_rpc::Error::Auth(_) => false,

            // URL parse errors are permanent
            bitcoincore_rpc::Error::UrlParse(_) => false,

            // Invalid cookie file is usually a config issue (permanent)
            bitcoincore_rpc::Error::InvalidCookieFile => false,

            // Daemon returned error - check the error message
            bitcoincore_rpc::Error::ReturnedError(error_msg) => {
                let error_str = error_msg.to_lowercase();
                // Retry on temporary RPC errors
                error_str.contains("loading") ||
                error_str.contains("warming up") ||
                error_str.contains("verifying") ||
                error_str.contains("busy") ||
                error_str.contains("temporary") ||
                error_str.contains("try again") ||
                error_str.contains("timeout") ||
                // Don't retry on wallet/transaction specific errors
                !(error_str.contains("insufficient funds") ||
                  error_str.contains("transaction already") ||
                  error_str.contains("invalid") ||
                  error_str.contains("not found") ||
                  error_str.contains("conflict"))
            }

            // Unexpected structure might be due to version mismatch or temporary parsing issues
            // Be conservative and retry once
            bitcoincore_rpc::Error::UnexpectedStructure => true,

            // Serialization errors are typically permanent
            bitcoincore_rpc::Error::BitcoinSerialization(_) => false,
            bitcoincore_rpc::Error::Hex(_) => false,
            bitcoincore_rpc::Error::Json(_) => false,
            bitcoincore_rpc::Error::Secp256k1(_) => false,
            bitcoincore_rpc::Error::InvalidAmount(_) => false,
        };
        tracing::trace!("Final is_retryable result: {}", result);
        result
    }
}

impl RetryableError for BitcoinRPCError {
    fn is_retryable(&self) -> bool {
        match self {
            BitcoinRPCError::TransactionNotConfirmed => true,
            BitcoinRPCError::TransactionAlreadyInBlock(_) => false,
            BitcoinRPCError::BumpFeeUTXOSpent(_) => false,

            // These might be temporary - retry
            BitcoinRPCError::BumpFeeError(_, _) => true,

            // Check underlying error
            BitcoinRPCError::Other(err) => {
                let err_str = err.to_string().to_lowercase();
                err_str.contains("timeout")
                    || err_str.contains("connection")
                    || err_str.contains("temporary")
                    || err_str.contains("busy")
                    || err_str.contains("network")
            }
        }
    }
}

/// Bitcoin RPC wrapper. Extended RPC provides useful wrapper functions for
/// common operations, as well as direct access to Bitcoin RPC.
#[derive(Clone)]
pub struct ExtendedBitcoinRpc {
    url: String,
    client: Arc<Client>,
    retry_config: RetryConfig,

    #[cfg(test)]
    cached_mining_address: Arc<tokio::sync::RwLock<Option<String>>>,
}

impl std::fmt::Debug for ExtendedBitcoinRpc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtendedBitcoinRpc")
            .field("url", &self.url)
            .finish()
    }
}

/// Errors that can occur during Bitcoin RPC operations.
#[derive(Debug, thiserror::Error)]
pub enum BitcoinRPCError {
    #[error("Failed to bump fee for Txid of {0} and feerate of {1}")]
    BumpFeeError(Txid, FeeRate),
    #[error("Failed to bump fee: UTXO is already spent")]
    BumpFeeUTXOSpent(OutPoint),
    #[error("Transaction is already in block: {0}")]
    TransactionAlreadyInBlock(BlockHash),
    #[error("Transaction is not confirmed")]
    TransactionNotConfirmed,

    #[error(transparent)]
    Other(#[from] eyre::Report),
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

                // Since this is a lazy connection, we should ping it to ensure it works
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
                    #[cfg(test)]
                    cached_mining_address: Arc::new(tokio::sync::RwLock::new(None)),
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

    /// Checks if an operator's collateral is valid and available for use.
    ///
    /// This function validates the operator's collateral by:
    /// 1. Verifying the collateral UTXO exists and has the correct amount
    /// 2. Creating the round transaction chain to track current collateral position
    /// 3. Determining if the current collateral UTXO in the chain is spent in a non-protocol tx, signaling the exit of operator from the protocol
    ///
    /// # Parameters
    ///
    /// * `operator_data`: Data about the operator including collateral funding outpoint
    /// * `kickoff_wpks`: Kickoff Winternitz public keys for round transaction creation
    /// * `paramset`: Protocol parameters
    ///
    /// # Returns
    ///
    /// - [`bool`]: `true` if the collateral is still usable, thus operator is still in protocol, `false` if the collateral is spent, thus operator is not in protocol anymore
    ///
    /// # Errors
    ///
    /// - [`BridgeError`]: If there was an error retrieving transaction data, creating round transactions,
    ///   or checking UTXO status
    pub async fn collateral_check(
        &self,
        operator_data: &OperatorData,
        kickoff_wpks: &KickoffWinternitzKeys,
        paramset: &'static ProtocolParamset,
    ) -> std::result::Result<bool, BridgeError> {
        // first check if the collateral utxo is on chain or mempool
        let tx = self
            .get_tx_of_txid(&operator_data.collateral_funding_outpoint.txid)
            .await
            .wrap_err(format!(
                "Failed to find collateral utxo in chain for outpoint {:?}",
                operator_data.collateral_funding_outpoint
            ))?;
        let collateral_outpoint = match tx
            .output
            .get(operator_data.collateral_funding_outpoint.vout as usize)
        {
            Some(output) => output,
            None => {
                tracing::warn!(
                    "No output at index {} for txid {} while checking for collateral existence",
                    operator_data.collateral_funding_outpoint.vout,
                    operator_data.collateral_funding_outpoint.txid
                );
                return Ok(false);
            }
        };

        if collateral_outpoint.value != paramset.collateral_funding_amount {
            tracing::error!(
                "Collateral amount for collateral {:?} is not correct: expected {}, got {}",
                operator_data.collateral_funding_outpoint,
                paramset.collateral_funding_amount,
                collateral_outpoint.value
            );
            return Ok(false);
        }

        let operator_tpr_address =
            create_taproot_address(&[], Some(operator_data.xonly_pk), paramset.network).0;

        if collateral_outpoint.script_pubkey != operator_tpr_address.script_pubkey() {
            tracing::error!(
                "Collateral script pubkey for collateral {:?} is not correct: expected {}, got {}",
                operator_data.collateral_funding_outpoint,
                operator_tpr_address.script_pubkey(),
                collateral_outpoint.script_pubkey
            );
            return Ok(false);
        }

        // we additionally check if collateral utxo is on chain (so not in mempool)
        // on mainnet we fail if collateral utxo is not on chain because if it is in mempool,
        // the txid of the utxo can change if the fee is bumped
        // on other networks, we allow collateral to be in mempool to not wait for collateral to be on chain to do deposits for faster testing
        let is_on_chain = self
            .is_tx_on_chain(&operator_data.collateral_funding_outpoint.txid)
            .await?;
        if !is_on_chain {
            return match paramset.network {
                bitcoin::Network::Bitcoin => Ok(false),
                _ => Ok(true),
            };
        }

        let mut current_collateral_outpoint: OutPoint = operator_data.collateral_funding_outpoint;
        let mut prev_ready_to_reimburse: Option<TxHandler> = None;
        // iterate over all rounds
        for round_idx in RoundIndex::iter_rounds(paramset.num_round_txs) {
            // create round and ready to reimburse txs for the round
            let txhandlers = create_round_txhandlers(
                paramset,
                round_idx,
                operator_data,
                kickoff_wpks,
                prev_ready_to_reimburse.as_ref(),
            )?;

            let mut round_txhandler_opt = None;
            let mut ready_to_reimburse_txhandler_opt = None;
            for txhandler in &txhandlers {
                match txhandler.get_transaction_type() {
                    TransactionType::Round => round_txhandler_opt = Some(txhandler),
                    TransactionType::ReadyToReimburse => {
                        ready_to_reimburse_txhandler_opt = Some(txhandler)
                    }
                    _ => {}
                }
            }
            if round_txhandler_opt.is_none() || ready_to_reimburse_txhandler_opt.is_none() {
                return Err(eyre!(
                    "Failed to create round and ready to reimburse txs for round {:?} for operator {}",
                    round_idx,
                    operator_data.xonly_pk
                ).into());
            }

            let round_txid = round_txhandler_opt
                .expect("Round txhandler should exist, checked above")
                .get_cached_tx()
                .compute_txid();
            let is_round_tx_on_chain = self.is_tx_on_chain(&round_txid).await?;
            if !is_round_tx_on_chain {
                break;
            }
            let block_hash = self.get_blockhash_of_tx(&round_txid).await?;
            let block_height = self
                .get_block_info(&block_hash)
                .await
                .wrap_err(format!(
                    "Failed to get block info for block hash {}",
                    block_hash
                ))?
                .height;
            if block_height < paramset.start_height as usize {
                tracing::warn!(
                    "Collateral utxo of operator {:?} is spent in a block before paramset start height: {} < {}",
                    operator_data,
                    block_height,
                    paramset.start_height
                );
                return Ok(false);
            }
            current_collateral_outpoint = OutPoint {
                txid: round_txid,
                vout: UtxoVout::CollateralInRound.get_vout(),
            };
            if round_idx == RoundIndex::Round(paramset.num_round_txs - 1) {
                // for the last round, only check round tx, as if the operator sent the ready to reimburse tx of last round,
                // it cannot create more kickoffs anymore
                break;
            }
            let ready_to_reimburse_txhandler = ready_to_reimburse_txhandler_opt
                .expect("Ready to reimburse txhandler should exist");
            let ready_to_reimburse_txid =
                ready_to_reimburse_txhandler.get_cached_tx().compute_txid();
            let is_ready_to_reimburse_tx_on_chain =
                self.is_tx_on_chain(&ready_to_reimburse_txid).await?;
            if !is_ready_to_reimburse_tx_on_chain {
                break;
            }

            current_collateral_outpoint = OutPoint {
                txid: ready_to_reimburse_txid,
                vout: UtxoVout::CollateralInReadyToReimburse.get_vout(),
            };

            prev_ready_to_reimburse = Some(ready_to_reimburse_txhandler.clone());
        }

        // if the collateral utxo we found latest in the round tx chain is spent, operators collateral is spent from Clementine
        // bridge protocol, thus it is unusable and operator cannot fulfill withdrawals anymore
        // if not spent, it should exist in chain, which is checked below
        Ok(!self.is_utxo_spent(&current_collateral_outpoint).await?)
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
            "Couldn't retrieve block hash from height {} from rpc",
            height
        ))?;
        let block_header = self.get_block_header(&block_hash).await.wrap_err(format!(
            "Couldn't retrieve block header with block hash {} from rpc",
            block_hash
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
        address: &ScriptBuf,
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
    #[cfg(test)]
    pub async fn mine_blocks(&self, block_num: u64) -> Result<Vec<BlockHash>> {
        if block_num == 0 {
            return Ok(vec![]);
        }

        self.try_mine(block_num).await
    }

    /// A helper fn to safely mine blocks while waiting for all actors to be synced
    #[cfg(test)]
    pub async fn mine_blocks_while_synced<C: CitreaClientT>(
        &self,
        block_num: u64,
        actors: &TestActors<C>,
    ) -> Result<Vec<BlockHash>> {
        let mut mined_blocks = Vec::new();
        while mined_blocks.len() < block_num as usize {
            if !are_all_state_managers_synced(self, actors).await? {
                // wait until they are synced
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                continue;
            }
            let new_blocks = self.mine_blocks(1).await?;
            mined_blocks.extend(new_blocks);
        }
        Ok(mined_blocks)
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
    #[cfg(test)]
    async fn try_mine(&self, block_num: u64) -> Result<Vec<BlockHash>> {
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
            .send_to_address(address, amount_sats, None, None, None, None, None, None)
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
        let tx_size = tx.weight().to_vbytes_ceil();
        let current_fee_sat = u64::try_from(
            transaction_info
                .fee
                .expect("Fee should be present")
                .to_sat()
                .abs(),
        )
        .wrap_err("Failed to convert fee to sat")?;

        let current_fee_rate = FeeRate::from_sat_per_kwu(1000 * current_fee_sat / tx_size);

        // If current fee rate is already sufficient, return original txid
        if current_fee_rate >= fee_rate {
            return Ok(txid);
        }

        // Get node's incremental fee to determine how much to increase
        let network_info = self
            .get_network_info()
            .await
            .wrap_err("Failed to get network info")?;
        let incremental_fee = network_info.incremental_fee;
        let incremental_fee_rate: FeeRate = FeeRate::from_sat_per_kwu(incremental_fee.to_sat());

        // Calculate new fee rate by adding incremental fee to current fee rate
        let new_fee_rate = FeeRate::from_sat_per_kwu(
            current_fee_rate.to_sat_per_kwu() + incremental_fee_rate.to_sat_per_kwu(),
        );

        tracing::debug!(
            "Bumping fee for txid: {txid} from {current_fee_rate} to {new_fee_rate} with incremental fee {incremental_fee_rate} - Final fee rate: {new_fee_rate}"
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

        // Return the new txid
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
            #[cfg(test)]
            cached_mining_address: self.cached_mining_address.clone(),
        })
    }
}

#[async_trait]
/// Implementation of the `RpcApi` trait for `ExtendedBitcoinRpc`. All RPC calls
/// are made with retry logic that only retries when errors are retryable.
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::actor::Actor;
    use crate::config::protocol::{ProtocolParamset, REGTEST_PARAMSET};
    use crate::extended_bitcoin_rpc::ExtendedBitcoinRpc;
    use crate::test::common::{citrea, create_test_config_with_thread_name};
    use crate::{
        bitvm_client::SECP, extended_bitcoin_rpc::BitcoinRPCError, test::common::create_regtest_rpc,
    };
    use bitcoin::Amount;
    use bitcoin::{amount, key::Keypair, Address, FeeRate, XOnlyPublicKey};
    use bitcoincore_rpc::RpcApi;
    use citrea_e2e::bitcoin::DEFAULT_FINALITY_DEPTH;
    use citrea_e2e::config::{BitcoinConfig, TestCaseDockerConfig};
    use citrea_e2e::node::NodeKind;
    use citrea_e2e::test_case::TestCaseRunner;
    use citrea_e2e::Result;
    use citrea_e2e::{config::TestCaseConfig, framework::TestFramework, test_case::TestCase};
    use tonic::async_trait;

    #[tokio::test]
    async fn new_extended_rpc_with_clone() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc();

        rpc.mine_blocks(101).await.unwrap();
        let height = rpc.get_block_count().await.unwrap();
        let hash = rpc.get_block_hash(height).await.unwrap();

        let cloned_rpc = rpc.clone_inner().await.unwrap();
        assert_eq!(cloned_rpc.url, rpc.url);
        assert_eq!(cloned_rpc.get_block_count().await.unwrap(), height);
        assert_eq!(cloned_rpc.get_block_hash(height).await.unwrap(), hash);
    }

    #[tokio::test]
    async fn tx_checks_in_mempool_and_on_chain() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc();

        let keypair = Keypair::from_secret_key(&SECP, &config.secret_key);
        let (xonly, _parity) = XOnlyPublicKey::from_keypair(&keypair);
        let address = Address::p2tr(&SECP, xonly, None, config.protocol_paramset.network);

        let amount = amount::Amount::from_sat(10000);

        // Prepare a transaction.
        let utxo = rpc.send_to_address(&address, amount).await.unwrap();
        let tx = rpc.get_tx_of_txid(&utxo.txid).await.unwrap();
        let txid = tx.compute_txid();
        tracing::debug!("TXID: {}", txid);

        assert_eq!(tx.output[utxo.vout as usize].value, amount);
        assert_eq!(utxo.txid, txid);
        assert!(rpc
            .check_utxo_address_and_amount(&utxo, &address.script_pubkey(), amount)
            .await
            .unwrap());

        // In mempool.
        assert!(rpc.confirmation_blocks(&utxo.txid).await.is_err());
        assert!(rpc.get_blockhash_of_tx(&utxo.txid).await.is_err());
        assert!(!rpc.is_tx_on_chain(&txid).await.unwrap());
        assert!(rpc.is_utxo_spent(&utxo).await.is_err());

        rpc.mine_blocks(1).await.unwrap();
        let height = rpc.get_block_count().await.unwrap();
        assert_eq!(height as u32, rpc.get_current_chain_height().await.unwrap());
        let blockhash = rpc.get_block_hash(height).await.unwrap();

        // On chain.
        assert_eq!(rpc.confirmation_blocks(&utxo.txid).await.unwrap(), 1);
        assert_eq!(
            rpc.get_blockhash_of_tx(&utxo.txid).await.unwrap(),
            blockhash
        );
        assert_eq!(rpc.get_tx_of_txid(&txid).await.unwrap(), tx);
        assert!(rpc.is_tx_on_chain(&txid).await.unwrap());
        assert!(!rpc.is_utxo_spent(&utxo).await.unwrap());

        // Doesn't matter if in mempool or on chain.
        let txout = rpc.get_txout_from_outpoint(&utxo).await.unwrap();
        assert_eq!(txout.value, amount);
        assert_eq!(rpc.get_tx_of_txid(&txid).await.unwrap(), tx);

        let height = rpc.get_current_chain_height().await.unwrap();
        let (hash, header) = rpc.get_block_info_by_height(height.into()).await.unwrap();
        assert_eq!(blockhash, hash);
        assert_eq!(rpc.get_block_header(&hash).await.unwrap(), header);
    }

    #[tokio::test]
    async fn bump_fee_with_fee_rate() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc();

        let keypair = Keypair::from_secret_key(&SECP, &config.secret_key);
        let (xonly, _parity) = XOnlyPublicKey::from_keypair(&keypair);
        let address = Address::p2tr(&SECP, xonly, None, config.protocol_paramset.network);

        let amount = amount::Amount::from_sat(10000);

        // Confirmed transaction cannot be fee bumped.
        let utxo = rpc.send_to_address(&address, amount).await.unwrap();
        rpc.mine_blocks(1).await.unwrap();
        assert!(rpc
            .bump_fee_with_fee_rate(utxo.txid, FeeRate::from_sat_per_vb(1).unwrap())
            .await
            .inspect_err(|e| {
                match e {
                    BitcoinRPCError::TransactionAlreadyInBlock(_) => {}
                    _ => panic!("Unexpected error: {:?}", e),
                }
            })
            .is_err());

        let current_fee_rate = FeeRate::from_sat_per_vb_unchecked(1);

        // Trying to bump a transaction with a fee rate that is already enough
        // should return the original txid.
        let utxo = rpc.send_to_address(&address, amount).await.unwrap();
        let txid = rpc
            .bump_fee_with_fee_rate(utxo.txid, current_fee_rate)
            .await
            .unwrap();
        assert_eq!(txid, utxo.txid);

        // A bigger fee rate should return a different txid.
        let new_fee_rate = FeeRate::from_sat_per_vb_unchecked(10000);
        let txid = rpc
            .bump_fee_with_fee_rate(utxo.txid, new_fee_rate)
            .await
            .unwrap();
        assert_ne!(txid, utxo.txid);
    }

    struct ReorgChecks;
    #[async_trait]
    impl TestCase for ReorgChecks {
        fn bitcoin_config() -> BitcoinConfig {
            BitcoinConfig {
                extra_args: vec![
                    "-txindex=1",
                    "-fallbackfee=0.000001",
                    "-rpcallowip=0.0.0.0/0",
                    "-dustrelayfee=0",
                ],
                ..Default::default()
            }
        }

        fn test_config() -> TestCaseConfig {
            TestCaseConfig {
                with_sequencer: true,
                with_batch_prover: false,
                n_nodes: HashMap::from([(NodeKind::Bitcoin, 2)]),
                docker: TestCaseDockerConfig {
                    bitcoin: true,
                    citrea: true,
                },
                ..Default::default()
            }
        }

        async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
            let (da0, da1) = (
                f.bitcoin_nodes.get(0).unwrap(),
                f.bitcoin_nodes.get(1).unwrap(),
            );

            let mut config = create_test_config_with_thread_name().await;
            const PARAMSET: ProtocolParamset = ProtocolParamset {
                finality_depth: DEFAULT_FINALITY_DEPTH as u32,
                ..REGTEST_PARAMSET
            };
            config.protocol_paramset = &PARAMSET;
            citrea::update_config_with_citrea_e2e_values(
                &mut config,
                da0,
                f.sequencer.as_ref().expect("Sequencer is present"),
                None,
            );

            let rpc = ExtendedBitcoinRpc::connect(
                config.bitcoin_rpc_url.clone(),
                config.bitcoin_rpc_user.clone(),
                config.bitcoin_rpc_password.clone(),
                None,
            )
            .await
            .unwrap();

            // Reorg starts here.
            f.bitcoin_nodes.disconnect_nodes().await?;

            let before_reorg_tip_height = rpc.get_block_count().await?;
            let before_reorg_tip_hash = rpc.get_block_hash(before_reorg_tip_height).await?;

            let address = Actor::new(config.secret_key, config.protocol_paramset.network).address;
            let tx = rpc
                .send_to_address(&address, Amount::from_sat(10000))
                .await?;

            assert!(!rpc.is_tx_on_chain(&tx.txid).await?);
            rpc.mine_blocks(1).await?;
            assert!(rpc.is_tx_on_chain(&tx.txid).await?);

            // Make the second branch longer and perform a reorg.
            let reorg_depth = 4;
            da1.generate(reorg_depth).await.unwrap();
            f.bitcoin_nodes.connect_nodes().await?;
            f.bitcoin_nodes.wait_for_sync(None).await?;

            // Check that reorg happened.
            let current_tip_height = rpc.get_block_count().await?;
            assert_eq!(
                before_reorg_tip_height + reorg_depth,
                current_tip_height,
                "Re-org did not occur"
            );
            let current_tip_hash = rpc.get_block_hash(current_tip_height).await?;
            assert_ne!(
                before_reorg_tip_hash, current_tip_hash,
                "Re-org did not occur"
            );

            assert!(!rpc.is_tx_on_chain(&tx.txid).await?);

            Ok(())
        }
    }

    #[tokio::test]
    async fn reorg_checks() -> Result<()> {
        TestCaseRunner::new(ReorgChecks).run().await
    }

    mod retry_config_tests {
        use crate::extended_bitcoin_rpc::RetryConfig;

        use std::time::Duration;

        #[test]
        fn test_retry_config_default() {
            let config = RetryConfig::default();
            assert_eq!(config.initial_delay_millis, 100);
            assert_eq!(config.max_delay, Duration::from_secs(30));
            assert_eq!(config.max_attempts, 5);
            assert_eq!(config.backoff_multiplier, 2);
            assert!(!config.is_jitter);
        }

        #[test]
        fn test_retry_config_custom() {
            let initial = 200;
            let max = Duration::from_secs(10);
            let attempts = 7;
            let backoff_multiplier = 3;
            let jitter = true;
            let config = RetryConfig::new(initial, max, attempts, backoff_multiplier, jitter);
            assert_eq!(config.initial_delay_millis, initial);
            assert_eq!(config.max_delay, max);
            assert_eq!(config.max_attempts, attempts);
            assert_eq!(config.backoff_multiplier, backoff_multiplier);
            assert!(config.is_jitter);
        }

        #[test]
        fn test_retry_strategy_initial_delay() {
            // Test that the first delay matches the expected initial_delay_millis
            // when initial_delay_millis is divisible by backoff_multiplier
            let initial_delay_millis = 100;
            let backoff_multiplier = 2;
            let config = RetryConfig::new(
                initial_delay_millis,
                Duration::from_secs(30),
                5,
                backoff_multiplier,
                false, // no jitter for predictable testing
            );

            let mut strategy = config.get_strategy();
            let first_delay = strategy.next().expect("Should have first delay");

            // The formula is: first_delay = base * factor
            // We set base = initial_delay_millis / backoff_multiplier
            // So: first_delay = (initial_delay_millis / backoff_multiplier) * backoff_multiplier = initial_delay_millis
            assert_eq!(
                first_delay,
                Duration::from_millis(initial_delay_millis),
                "First delay should match initial_delay_millis"
            );

            // Verify the second delay is approximately initial_delay_millis * backoff_multiplier
            let second_delay = strategy.next().expect("Should have second delay");
            assert_eq!(
                second_delay,
                Duration::from_millis(initial_delay_millis * backoff_multiplier),
                "Second delay should be initial_delay_millis * backoff_multiplier"
            );
        }
    }

    mod retryable_error_tests {
        use bitcoin::{hashes::Hash, BlockHash, Txid};

        use crate::extended_bitcoin_rpc::RetryableError;

        use super::*;
        use std::io::{Error as IoError, ErrorKind};

        #[test]
        fn test_bitcoin_rpc_error_retryable_io_errors() {
            let retryable_kinds = [
                ErrorKind::ConnectionRefused,
                ErrorKind::ConnectionReset,
                ErrorKind::ConnectionAborted,
                ErrorKind::NotConnected,
                ErrorKind::BrokenPipe,
                ErrorKind::TimedOut,
                ErrorKind::Interrupted,
                ErrorKind::UnexpectedEof,
            ];

            for kind in retryable_kinds {
                let io_error = IoError::new(kind, "test error");
                let rpc_error = bitcoincore_rpc::Error::Io(io_error);
                assert!(
                    rpc_error.is_retryable(),
                    "ErrorKind::{:?} should be retryable",
                    kind
                );
            }
        }

        #[test]
        fn test_bitcoin_rpc_error_non_retryable_io_errors() {
            let non_retryable_kinds = [
                ErrorKind::PermissionDenied,
                ErrorKind::NotFound,
                ErrorKind::InvalidInput,
                ErrorKind::InvalidData,
            ];

            for kind in non_retryable_kinds {
                let io_error = IoError::new(kind, "test error");
                let rpc_error = bitcoincore_rpc::Error::Io(io_error);
                assert!(
                    !rpc_error.is_retryable(),
                    "ErrorKind::{:?} should not be retryable",
                    kind
                );
            }
        }

        #[test]
        fn test_bitcoin_rpc_error_auth_not_retryable() {
            let auth_error = bitcoincore_rpc::Error::Auth("Invalid credentials".to_string());
            assert!(!auth_error.is_retryable());
        }

        #[test]
        fn test_bitcoin_rpc_error_url_parse_not_retryable() {
            let url_error = url::ParseError::EmptyHost;
            let rpc_error = bitcoincore_rpc::Error::UrlParse(url_error);
            assert!(!rpc_error.is_retryable());
        }

        #[test]
        fn test_bitcoin_rpc_error_invalid_cookie_not_retryable() {
            let rpc_error = bitcoincore_rpc::Error::InvalidCookieFile;
            assert!(!rpc_error.is_retryable());
        }

        #[test]
        fn test_bitcoin_rpc_error_returned_error_non_retryable_patterns() {
            let non_retryable_messages = [
                "insufficient funds",
                "transaction already in blockchain",
                "invalid transaction",
                "not found in mempool",
                "transaction conflict",
            ];

            for msg in non_retryable_messages {
                let rpc_error = bitcoincore_rpc::Error::ReturnedError(msg.to_string());
                assert!(
                    !rpc_error.is_retryable(),
                    "Message '{}' should not be retryable",
                    msg
                );
            }
        }

        #[test]
        fn test_bitcoin_rpc_error_unexpected_structure_retryable() {
            let rpc_error = bitcoincore_rpc::Error::UnexpectedStructure;
            assert!(rpc_error.is_retryable());
        }

        #[test]
        fn test_bitcoin_rpc_error_serialization_errors_not_retryable() {
            use bitcoin::consensus::encode::Error as EncodeError;

            let serialization_errors = [
                bitcoincore_rpc::Error::BitcoinSerialization(EncodeError::Io(
                    IoError::new(ErrorKind::Other, "test").into(),
                )),
                // bitcoincore_rpc::Error::Hex(HexToBytesError::InvalidChar(InvalidCharError{invalid: 0})),
                bitcoincore_rpc::Error::Json(serde_json::Error::io(IoError::new(
                    ErrorKind::Other,
                    "test",
                ))),
            ];

            for error in serialization_errors {
                assert!(
                    !error.is_retryable(),
                    "Serialization error should not be retryable"
                );
            }
        }

        #[test]
        fn test_bridge_rpc_error_retryable() {
            // Test permanent errors
            assert!(
                !BitcoinRPCError::TransactionAlreadyInBlock(BlockHash::all_zeros()).is_retryable()
            );
            assert!(!BitcoinRPCError::BumpFeeUTXOSpent(Default::default()).is_retryable());

            // Test potentially retryable errors
            let txid = Txid::all_zeros();
            let fee_rate = FeeRate::from_sat_per_vb_unchecked(1);
            assert!(BitcoinRPCError::BumpFeeError(txid, fee_rate).is_retryable());

            // Test Other error with retryable patterns
            let retryable_other = BitcoinRPCError::Other(eyre::eyre!("timeout occurred"));
            assert!(retryable_other.is_retryable());

            let non_retryable_other = BitcoinRPCError::Other(eyre::eyre!("permission denied"));
            assert!(!non_retryable_other.is_retryable());
        }
    }

    mod rpc_call_retry_tests {

        use crate::extended_bitcoin_rpc::RetryableError;

        use super::*;
        use secrecy::SecretString;

        #[tokio::test]
        async fn test_rpc_call_retry_with_invalid_credentials() {
            let mut config = create_test_config_with_thread_name().await;
            let regtest = create_regtest_rpc(&mut config).await;

            // Get a working connection first
            let working_rpc = regtest.rpc();
            let url = working_rpc.url.clone();

            // Create connection with invalid credentials
            let invalid_user = SecretString::new("invalid_user".to_string().into());
            let invalid_password = SecretString::new("invalid_password".to_string().into());

            let res = ExtendedBitcoinRpc::connect(url, invalid_user, invalid_password, None).await;

            assert!(res.is_err());
            assert!(!res.unwrap_err().is_retryable());
        }

        #[tokio::test]
        async fn test_rpc_call_retry_with_invalid_host() {
            let user = SecretString::new("user".to_string().into());
            let password = SecretString::new("password".to_string().into());
            let invalid_url = "http://nonexistent-host:8332".to_string();

            let res = ExtendedBitcoinRpc::connect(invalid_url, user, password, None).await;

            assert!(res.is_err());
            assert!(!res.unwrap_err().is_retryable());
        }
    }

    mod convenience_method_tests {
        use super::*;

        #[tokio::test]
        async fn test_get_block_hash_with_retry() {
            let mut config = create_test_config_with_thread_name().await;
            let regtest = create_regtest_rpc(&mut config).await;
            let rpc = regtest.rpc();

            // Mine a block first
            rpc.mine_blocks(1).await.unwrap();
            let height = rpc.get_block_count().await.unwrap();

            let result = rpc.get_block_hash(height).await;
            assert!(result.is_ok());

            let expected_hash = rpc.get_block_hash(height).await.unwrap();
            assert_eq!(result.unwrap(), expected_hash);
        }

        #[tokio::test]
        async fn test_get_tx_out_with_retry() {
            let mut config = create_test_config_with_thread_name().await;
            let regtest = create_regtest_rpc(&mut config).await;
            let rpc = regtest.rpc();

            // Create a transaction
            let keypair = Keypair::from_secret_key(&SECP, &config.secret_key);
            let (xonly, _parity) = XOnlyPublicKey::from_keypair(&keypair);
            let address = Address::p2tr(&SECP, xonly, None, config.protocol_paramset.network);
            let amount = Amount::from_sat(10000);

            let utxo = rpc.send_to_address(&address, amount).await.unwrap();

            let result = rpc.get_tx_of_txid(&utxo.txid).await;
            assert!(result.is_ok());

            let tx = result.unwrap();
            assert_eq!(tx.compute_txid(), utxo.txid);
        }

        #[tokio::test]
        async fn test_send_to_address_with_retry() {
            let mut config = create_test_config_with_thread_name().await;
            let regtest = create_regtest_rpc(&mut config).await;
            let rpc = regtest.rpc();

            let keypair = Keypair::from_secret_key(&SECP, &config.secret_key);
            let (xonly, _parity) = XOnlyPublicKey::from_keypair(&keypair);
            let address = Address::p2tr(&SECP, xonly, None, config.protocol_paramset.network);
            let amount = Amount::from_sat(10000);

            let result = rpc.send_to_address(&address, amount).await;
            assert!(result.is_ok());

            let outpoint = result.unwrap();

            // Verify the transaction exists
            let tx = rpc.get_tx_of_txid(&outpoint.txid).await.unwrap();
            assert_eq!(tx.output[outpoint.vout as usize].value, amount);
        }

        #[tokio::test]
        async fn test_bump_fee_with_retry() {
            let mut config = create_test_config_with_thread_name().await;
            let regtest = create_regtest_rpc(&mut config).await;
            let rpc = regtest.rpc();

            let keypair = Keypair::from_secret_key(&SECP, &config.secret_key);
            let (xonly, _parity) = XOnlyPublicKey::from_keypair(&keypair);
            let address = Address::p2tr(&SECP, xonly, None, config.protocol_paramset.network);
            let amount = Amount::from_sat(10000);

            // Create an unconfirmed transaction
            let utxo = rpc.send_to_address(&address, amount).await.unwrap();
            let new_fee_rate = FeeRate::from_sat_per_vb_unchecked(10000);

            let result = rpc.bump_fee_with_fee_rate(utxo.txid, new_fee_rate).await;
            assert!(result.is_ok());

            let new_txid = result.unwrap();
            // Should return a different txid since fee was actually bumped
            assert_ne!(new_txid, utxo.txid);
        }
    }
}
