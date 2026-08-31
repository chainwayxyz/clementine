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
use bitcoin::{
    Address, Amount, BlockHash, FeeRate, Network, OutPoint, ScriptBuf, Transaction, TxOut, Txid,
    XOnlyPublicKey,
};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use eyre::{eyre, Context, OptionExt};
use http::StatusCode;
use reqwest;
use secrecy::{ExposeSecret, SecretString};
use std::{
    collections::{HashMap, HashSet},
    iter::Take,
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use tokio::time::timeout;
use tokio_retry::{
    strategy::{jitter, ExponentialBackoff},
    RetryIf,
};

use crate::{
    bitvm_client::ClementineBitVMPublicKeys,
    builder::{
        address::create_taproot_address,
        transaction::{
            create_round_txhandlers, input::UtxoVout, KickoffWinternitzKeys, TransactionType,
            TxHandler,
        },
    },
    config::protocol::ProtocolParamset,
    constants::NON_STANDARD_V3,
    database::Database,
    deposit::OperatorData,
    errors::{BridgeError, FeeErr},
    operator::RoundIndex,
};
use circuits_lib::{bridge_circuit::parse_op_return_data, common::constants::FIRST_FIVE_OUTPUTS};

#[cfg(test)]
use crate::test::common::citrea::CitreaE2EData;
#[cfg(test)]
use crate::{
    citrea::CitreaClientT,
    test::common::{are_all_nodes_synced, test_actors::TestActors},
};

type Result<T> = std::result::Result<T, BitcoinRPCError>;

const MAX_RETRY_ATTEMPTS: usize = 50;

/// `RPC_INVALID_ADDRESS_OR_KEY`. Returned by `getrawtransaction` when the transaction is in neither
/// the mempool nor the chain.
pub const RPC_INVALID_ADDRESS_OR_KEY: i32 = -5;

/// `RPC_INVALID_PARAMETER`. Returned by `getblockhash` when the requested height is above the tip.
pub const RPC_INVALID_PARAMETER: i32 = -8;

/// Returns the JSON-RPC error code when `error` is an error Bitcoin Core itself reported, and
/// `None` for transport, authentication and deserialization failures.
///
/// Use this to tell "the node answered, and the answer is no" apart from "we could not ask the
/// node". Collapsing the two makes a broken connection look like an empty chain or a missing
/// transaction.
pub fn rpc_error_code(error: &bitcoincore_rpc::Error) -> Option<i32> {
    match error {
        bitcoincore_rpc::Error::JsonRpc(bitcoincore_rpc::RpcError::Rpc(rpc_error)) => {
            Some(rpc_error.code)
        }
        _ => None,
    }
}

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
        let factor: u64 = initial_delay_millis / backoff_multiplier;

        let max_attempts = std::cmp::min(max_attempts, MAX_RETRY_ATTEMPTS);

        // Create the base strategy once
        let base_strategy = Arc::new(
            ExponentialBackoff::from_millis(backoff_multiplier)
                .max_delay(max_delay)
                .factor(factor)
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

/// JSON-RPC application codes for a node that is not ready.
const RPC_CLIENT_NOT_CONNECTED: i32 = -9;
const RPC_CLIENT_IN_INITIAL_DOWNLOAD: i32 = -10;
const RPC_IN_WARMUP_CODE: i32 = -28;

/// Returns true when an RPC application error is safe to retry.
///
/// Bitcoin Core emits `RPC_IN_WARMUP` from the RPC dispatcher before it calls
/// the command. The other transient codes are command-level errors and do not
/// prove that an arbitrary command had no effect. They are retried only when
/// repeating the command after an unknown outcome is safe.
fn is_retryable_rpc_code(code: i32, safe_after_unknown_outcome: bool) -> bool {
    code == RPC_IN_WARMUP_CODE
        || (safe_after_unknown_outcome
            && matches!(
                code,
                RPC_CLIENT_NOT_CONNECTED | RPC_CLIENT_IN_INITIAL_DOWNLOAD
            ))
}

/// Connection drops that can appear as I/O sources under a decode-kind reqwest
/// error when the peer resets or aborts while the response body is still being
/// read. Clean EOF (`UnexpectedEof`) is included; HTTP 401/404 empty bodies do
/// not produce these kinds.
fn is_connection_drop_io(error: &std::io::Error) -> bool {
    use std::io::ErrorKind;

    matches!(
        error.kind(),
        ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::BrokenPipe
            | ErrorKind::TimedOut
            | ErrorKind::UnexpectedEof
    )
}

/// Returns true if a decode-kind reqwest error was caused by the connection
/// dropping mid-response (transport EOF) instead of a malformed or empty
/// (e.g. HTTP 401/404) response body. reqwest's `Decoder` reports a body
/// closed before its Content-Length completes as `is_decode`, with a
/// `hyper::Error` (incomplete message) or a connection-drop `io::Error`
/// source; genuine JSON syntax errors have a plain `serde_json::Error`
/// source instead.
fn is_transport_eof_decode(error: &reqwest::Error) -> bool {
    if !error.is_decode() {
        return false;
    }

    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        if cause
            .downcast_ref::<hyper::Error>()
            .is_some_and(hyper::Error::is_incomplete_message)
        {
            return true;
        }
        if cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(is_connection_drop_io)
        {
            return true;
        }
        source = cause.source();
    }
    false
}

/// Returns true for reqwest transport errors that are safe to retry.
///
/// - Connect failures never reached the server: always safe.
/// - Mid-flight failures (request timeout, connection dropped while sending
///   the request or while streaming the response) are only safe when
///   `allow_mid_flight` is set, i.e. the command is idempotent: the server
///   may have already applied a mutating command, and re-issuing it would
///   apply it twice (double spend, extra blocks).
/// - Unparsable responses ([`reqwest::Error::is_decode`]) are never
///   retryable: bitcoind answers HTTP rejections such as 401 (bad auth) or
///   404 (unknown wallet) with a non-JSON body, which surfaces as a decode
///   error. Decode errors caused by transport EOF ([`is_transport_eof_decode`])
///   are the exception: they are mid-flight failures.
fn is_retryable_transport_error(
    error: &(dyn std::error::Error + 'static),
    allow_mid_flight: bool,
) -> bool {
    let Some(reqwest_error) = error.downcast_ref::<reqwest::Error>() else {
        return false;
    };

    reqwest_error.is_connect()
        || (allow_mid_flight
            && (reqwest_error.is_timeout()
                || reqwest_error.is_request()
                || reqwest_error.is_body()
                || is_transport_eof_decode(reqwest_error)))
}

/// Classifies local I/O failures without retrying known permanent errors.
fn is_retryable_io_error(error: &std::io::Error) -> bool {
    use std::io::ErrorKind;

    match error.kind() {
        ErrorKind::ConnectionRefused
        | ErrorKind::ConnectionReset
        | ErrorKind::ConnectionAborted
        | ErrorKind::NotConnected
        | ErrorKind::BrokenPipe
        | ErrorKind::TimedOut
        | ErrorKind::Interrupted
        | ErrorKind::UnexpectedEof => true,
        ErrorKind::PermissionDenied
        | ErrorKind::NotFound
        | ErrorKind::InvalidInput
        | ErrorKind::InvalidData => false,
        _ => true,
    }
}

/// Returns true when repeating an RPC after an unknown outcome is safe and useful.
///
/// Commands with side effects or duplicate-in-progress failures are deliberately
/// absent. A retry-safe command missing from this list merely means its mid-flight
/// failures are not retried (conservative).
fn is_safe_to_repeat_after_unknown_outcome(cmd: &str) -> bool {
    matches!(
        cmd,
        // Chain and block queries
        "getbestblockhash"
            | "getblock"
            | "getblockchaininfo"
            | "getblockcount"
            | "getblockhash"
            | "getblockheader"
            | "getchaintips"
            | "getdeploymentinfo"
            | "getindexinfo"
            // Mempool and transaction queries
            | "getmempoolentry"
            | "getmempoolinfo"
            | "getrawmempool"
            | "getrawtransaction"
            | "gettxout"
            | "gettxspendingprevout"
            | "testmempoolaccept"
            // Fee estimation
            | "estimatesmartfee"
            | "estimaterawfee"
            // Node status
            | "getaddednodeinfo"
            | "getmemoryinfo"
            | "getmininginfo"
            | "getnetworkinfo"
            | "getpeerinfo"
            | "getrpcinfo"
            | "ping"
            | "uptime"
            // Wallet read-only queries
            | "deriveaddresses"
            | "getaddressinfo"
            | "getbalance"
            | "getbalances"
            | "getdescriptorinfo"
            | "gettransaction"
            | "getwalletinfo"
            | "listdescriptors"
            | "listunspent"
            | "listwalletdir"
            | "listwallets"
            // Stateless signing: no wallet or chain state change; a repeat
            // after an unknown outcome returns an equally valid result.
            | "signrawtransactionwithwallet"
            | "walletprocesspsbt"
            // Same hex is idempotent. Retrying avoids CPFP/withdraw funding a
            // new tx when the first send was accepted but the response dropped.
            | "sendrawtransaction"
            | "submitpackage"
    )
}

/// Command-aware retry classification for individual RPC calls.
///
/// Definite reqwest connection failures never reached the server and are safe
/// for every command. All errors with an unknown outcome are retried only for
/// commands that are safe to repeat. This fail-closed rule prevents retries
/// from repeating wallet-funded sends, fee bumps, or other monetary effects.
fn is_retryable_for_command(cmd: &str, error: &bitcoincore_rpc::Error) -> bool {
    let safe_after_unknown_outcome = is_safe_to_repeat_after_unknown_outcome(cmd);

    match error {
        bitcoincore_rpc::Error::JsonRpc(bitcoincore_rpc::RpcError::Transport(transport_error)) => {
            is_retryable_transport_error(transport_error.as_ref(), safe_after_unknown_outcome)
        }
        bitcoincore_rpc::Error::JsonRpc(bitcoincore_rpc::RpcError::Rpc(rpc_error)) => {
            is_retryable_rpc_code(rpc_error.code, safe_after_unknown_outcome)
        }
        // This error does not record whether the I/O failure happened before
        // or after dispatch, so treat its outcome as unknown.
        bitcoincore_rpc::Error::Io(io_error) => {
            safe_after_unknown_outcome && is_retryable_io_error(io_error)
        }
        _ => false,
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
    /// Connects to Bitcoin RPC server and checks that the node answers.
    ///
    /// `Client::new` is lazy. The live check is `ping`, which goes through
    /// [`RpcApi::call`] and the same command-aware retry path as every other RPC.
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
    /// - [`BitcoinRPCError`]: If the client cannot be created, or ping fails after retries
    pub async fn connect(
        url: String,
        user: SecretString,
        password: SecretString,
        retry_config: Option<RetryConfig>,
    ) -> Result<Self> {
        let retry_config = retry_config.unwrap_or_default();
        let auth = Auth::UserPass(
            user.expose_secret().to_string(),
            password.expose_secret().to_string(),
        );

        tracing::debug!(
            "Attempting to connect to Bitcoin RPC at {} with retry config: {:?}",
            &url,
            &retry_config
        );
        // Client::new only stores URL and auth; it does not open a socket.
        let client = Client::new(&url, auth)
            .await
            .wrap_err("Failed to connect to Bitcoin RPC")?;

        let rpc = Self {
            url,
            client: Arc::new(client),
            retry_config,
            #[cfg(test)]
            cached_mining_address: Arc::new(tokio::sync::RwLock::new(None)),
        };

        tracing::debug!(
            "Pinging Bitcoin RPC at {} to make sure it's alive",
            &rpc.url
        );
        rpc.ping().await.wrap_err("Failed to ping Bitcoin RPC")?;

        tracing::debug!("Connected to Bitcoin RPC successfully");
        Ok(rpc)
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

    /// Checks if an operator is still safely usable in the protocol.
    ///
    /// This validates:
    /// 1. The collateral UTXO exists with the correct amount and script
    /// 2. The round chain is followed to the current collateral position
    /// 3. The current collateral is not spent outside the protocol
    /// 4. Every already-passed round (ready-to-reimburse is on chain) has no leftover
    ///    kickoff UTXOs. UnspentKickoff cannot slash those once the next round spends
    ///    the ready-to-reimburse burn connector, so leftover kickoffs can later be used
    ///    with already-mined reimburse connectors.
    /// 5. If a passed-round kickoff UTXO was spent as a kickoff, that kickoff's finalizer
    ///    must also be spent. An in-flight kickoff in a passed round is not watched by the
    ///    round state machine. This uses the actual spending transaction of each leftover
    ///    kickoff UTXO, including kickoffs that commit to a deposit that is not yet signed.
    ///
    /// `db` is the bitcoin syncer. Kickoff UTXOs of finished rounds are looked
    /// up there; we only load block bodies for spends that might be kickoffs.
    ///
    /// Spent-or-not comes from the syncer, not from bitcoind. If the syncer has
    /// no spend for a kickoff UTXO, treat it as still live and reject.
    /// A short mismatch with bitcoind is fine on mainnet.
    ///
    /// # Returns
    ///
    /// - [`bool`]: `true` if the operator is still in protocol and safe to include in deposits
    pub async fn collateral_check(
        &self,
        operator_data: &OperatorData,
        kickoff_wpks: &KickoffWinternitzKeys,
        paramset: &'static ProtocolParamset,
        db: &Database,
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
                    "Failed to get block info for block hash {block_hash}"
                ))?
                .height;
            if block_height < paramset.start_height as usize {
                tracing::warn!(
                    "Collateral utxo of operator {operator_data:?} is spent in a block before paramset start height: {block_height} < {0}",
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

            // Ready-to-reimburse is on chain, so this round is passed. Leftover
            // kickoffs can no longer be slashed via UnspentKickoff once the next
            // round spends that burn connector.
            let round_txhandler =
                round_txhandler_opt.expect("Round txhandler should exist, checked above");
            if !self
                .passed_round_kickoffs_are_safe(
                    round_txhandler,
                    round_idx,
                    paramset,
                    operator_data,
                    db,
                )
                .await?
            {
                return Ok(false);
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

    /// Returns false if a passed round still has a live kickoff UTXO, or an
    /// in-flight kickoff whose finalizer is unspent.
    ///
    /// Kickoff UTXOs of this finished round must all be spent. Spent-or-not
    /// comes from the syncer, not from bitcoind. No spend row means the UTXO
    /// is still live: reject. Do not add a `gettxout` check. A short mismatch
    /// with bitcoind is fine on mainnet.
    ///
    /// A tx that spends more than one of these UTXOs cannot be a protocol
    /// kickoff (those have a single input), so it is a burn and its block is
    /// not loaded. Other spends are loaded from their blocks. Sequence is the
    /// first filter: burn / UnspentKickoff set CSV, so a relative locktime
    /// cannot be a kickoff. After that it is a protocol kickoff only if it has
    /// exactly one input, version 3, the kickoff output layout, and the kickoff
    /// OP_RETURN (`move_txid || this operator's xonly pk`). Any other Winternitz
    /// spend still uses up the UTXO.
    async fn passed_round_kickoffs_are_safe(
        &self,
        round_txhandler: &TxHandler,
        round_idx: RoundIndex,
        paramset: &'static ProtocolParamset,
        operator_data: &OperatorData,
        db: &Database,
    ) -> std::result::Result<bool, BridgeError> {
        let mut kickoff_outpoints = Vec::with_capacity(paramset.num_kickoffs_per_round);
        for kickoff_idx in 0..paramset.num_kickoffs_per_round {
            kickoff_outpoints.push(
                *round_txhandler
                    .get_spendable_output(UtxoVout::Kickoff(kickoff_idx))?
                    .get_prev_outpoint(),
            );
        }
        let mut dbtx = db.begin_transaction().await?;
        let spends = db
            .get_canonical_spending_txids(Some(&mut dbtx), &kickoff_outpoints)
            .await?;

        let mut spend_count: HashMap<Txid, usize> = HashMap::new();
        for (spending_txid, _) in spends.values() {
            *spend_count.entry(*spending_txid).or_default() += 1;
        }

        let mut to_classify = Vec::new();
        let mut wanted_txids = HashSet::new();
        let mut unique_blockhashes = HashSet::new();
        for (kickoff_idx, kickoff_outpoint) in kickoff_outpoints.iter().enumerate() {
            let Some((spending_txid, blockhash)) = spends.get(kickoff_outpoint) else {
                tracing::error!(
                    ?operator_data,
                    ?round_idx,
                    kickoff_idx,
                    %kickoff_outpoint,
                    "Passed round has an unspent kickoff UTXO; operator is not safe to include in deposits"
                );
                dbtx.commit().await?;
                return Ok(false);
            };
            // A tx that consumes more than one leftover kickoff in this round cannot
            // be a protocol kickoff (those have a single input).
            if spend_count[spending_txid] > 1 {
                continue;
            }
            to_classify.push((*kickoff_outpoint, *spending_txid));
            wanted_txids.insert(*spending_txid);
            unique_blockhashes.insert(*blockhash);
        }

        // It is assumed that the number of unique block hashes is small, so we can fetch all the transactions in one query.
        // It will be obvious on mainnet if an operator intentionally tries to grief this.
        let spending_txs = db
            .get_txs_from_block_hashes(Some(&mut dbtx), unique_blockhashes, &wanted_txids)
            .await?;

        let mut finalizer_outpoints = Vec::new();
        for (kickoff_outpoint, spending_txid) in to_classify {
            let Some(spending_tx) = spending_txs.get(&spending_txid) else {
                return Err(eyre!(
                    "Canonical spending txid {spending_txid} was indexed but missing from its block"
                )
                .into());
            };
            if spending_is_protocol_kickoff(kickoff_outpoint, spending_tx, operator_data.xonly_pk)?
            {
                finalizer_outpoints.push(OutPoint {
                    txid: spending_txid,
                    vout: UtxoVout::KickoffFinalizer.get_vout(),
                });
            }
        }

        if !finalizer_outpoints.is_empty() {
            let spent_finalizers = db
                .get_canonical_spending_txids(Some(&mut dbtx), &finalizer_outpoints)
                .await?;
            if let Some(finalizer) = finalizer_outpoints
                .iter()
                .find(|outpoint| !spent_finalizers.contains_key(outpoint))
            {
                tracing::error!(
                    ?operator_data,
                    ?round_idx,
                    %finalizer,
                    "Passed round kickoff UTXO was spent as a kickoff but the kickoff finalizer is still unspent"
                );
                dbtx.commit().await?;
                return Ok(false);
            }
        }
        dbtx.commit().await?;
        Ok(true)
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
    ///
    /// # Errors
    ///
    /// Only an unknown transaction yields `Ok(false)`. Any other RPC failure is returned as an
    /// error: callers use this to decide whether collateral is still present and whether round
    /// transactions have landed, so a transport failure must not be reported as "not on chain".
    pub async fn is_tx_on_chain(&self, txid: &bitcoin::Txid) -> Result<bool> {
        match self.get_raw_transaction_info(txid, None).await {
            Ok(info) => Ok(info.blockhash.is_some()),
            Err(e) if rpc_error_code(&e) == Some(RPC_INVALID_ADDRESS_OR_KEY) => Ok(false),
            Err(e) => Err(eyre::eyre!(e)
                .wrap_err(format!("Failed to look up transaction {txid}"))
                .into()),
        }
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
    /// If CitreaE2EData is provided and there are multiple DA nodes, it will additionally perform a reorg. Reorg will cause chain size to increase by number of reorged blocks in addition to block_num.
    #[cfg(test)]
    pub async fn mine_blocks_while_synced<C: CitreaClientT>(
        &self,
        block_num: u64,
        actors: &TestActors<C>,
        e2e: Option<&CitreaE2EData<'_>>,
    ) -> Result<Vec<BlockHash>> {
        match e2e {
            // do a reorg if there are multiple nodes, the actors are currently always using node 0
            Some(e2e) if e2e.bitcoin_nodes.iter().count() > 1 => {
                use bitcoin::secp256k1::rand::{thread_rng, Rng};
                e2e.bitcoin_nodes
                    .disconnect_nodes()
                    .await
                    .map_err(|e| eyre::eyre!("Failed to disconnect nodes: {}", e))?;
                let reorg_blocks =
                    thread_rng().gen_range(0..e2e.config.protocol_paramset().finality_depth as u64);
                let da0 = e2e.bitcoin_nodes.get(0).expect("node 0 should exist");
                let da1 = e2e.bitcoin_nodes.get(1).expect("node 1 should exist");

                let mut mined_blocks = Vec::new();
                while mined_blocks.len() < reorg_blocks as usize {
                    if !are_all_nodes_synced(self, actors).await? {
                        // wait until they are synced
                        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                        continue;
                    }
                    da0.generate(1)
                        .await
                        .wrap_err("Failed to generate blocks")?;
                    // da1 will be canonical
                    let new_blocks = da1
                        .generate(1)
                        .await
                        .wrap_err("Failed to generate blocks")?;
                    mined_blocks.extend(new_blocks);
                }
                mined_blocks.extend(
                    da1.generate(1)
                        .await
                        .wrap_err("Failed to generate blocks")?,
                );
                // connect and reorg, da0's blocks will be non-canonical
                e2e.bitcoin_nodes
                    .connect_nodes()
                    .await
                    .map_err(|e| eyre::eyre!("Failed to connect nodes: {}", e))?;
                e2e.bitcoin_nodes
                    .wait_for_sync(None)
                    .await
                    .map_err(|e| eyre::eyre!("Failed to wait for sync: {}", e))?;
                // mined blocks has to be block_num higher than reorg_blocks + 1, because this callers of this fn expects
                // chain size to increase by at least block_num starting from where cpfp fee payer is in mempool.
                while mined_blocks.len() != (reorg_blocks + block_num + 1) as usize {
                    if !are_all_nodes_synced(self, actors).await? {
                        // wait until they are synced
                        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                        continue;
                    }
                    mined_blocks.extend(self.mine_blocks(1).await?);
                }
                Ok(mined_blocks)
            }
            _ => {
                // do not do a reorg here, just mine blocks
                let mut mined_blocks = Vec::new();
                while mined_blocks.len() < block_num as usize {
                    if !are_all_nodes_synced(self, actors).await? {
                        // wait until they are synced
                        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                        continue;
                    }
                    let new_blocks = self.mine_blocks(1).await?;
                    mined_blocks.extend(new_blocks);
                }
                Ok(mined_blocks)
            }
        }
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
        if let Some(blockhash) = transaction_info.info.blockhash {
            return Err(BitcoinRPCError::TransactionAlreadyInBlock(blockhash));
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
                        .into());
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
                        tracing::debug!(
                            "RPC fee estimation failed, using mempool.space: {:#}",
                            rpc_err
                        );
                        mempool_amt
                    }
                    (Err(mempool_err), Ok(rpc_amt)) => {
                        tracing::debug!(
                            "Mempool.space fee fetch failed, using Bitcoin Core RPC: {:#}",
                            mempool_err
                        );
                        rpc_amt
                    }
                    (Err(mempool_err), Err(rpc_err)) => {
                        tracing::warn!(
                            "Both fee sources failed (mempool: {:#}, rpc: {:#}), using default of 1 sat/vB",
                            mempool_err,
                            rpc_err
                        );
                        Amount::from_sat(1000) // 1 sat/vB * 1000 = 1000 sat/kvB
                    }
                };

                // Convert sat/kvB to sat/vB and apply hard cap
                let mut fee_sat_kvb = selected_fee_amount.to_sat();

                // Apply hard cap from config
                if fee_sat_kvb > fee_rate_hard_cap * 1000 {
                    tracing::debug!(
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
            "{url}{endpoint}",
        ),
        Network::Testnet4 => format!("{url}testnet4/{endpoint}"),
        // Return early with error for unsupported networks
        Network::Signet => {
            tracing::debug!("You should use Citrea signet url for mempool.space");
            format!("{url}{endpoint}")
        }
        _ => return Err(eyre!("Unsupported network for mempool.space: {network:?}").into()),
    };

    let retry_config = RetryConfig::new(250, Duration::from_secs(5), 4, 2, true);

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
    .wrap_err_with(|| format!("Failed to fetch/parse fees from {url}"))?;

    // The API returns the fee rate in sat/vB. We multiply by 1000 to get sat/kvB.
    let fee_rate = Amount::from_sat(fee_sat_per_vb * 1000);

    Ok(fee_rate)
}

/// Challenge, KickoffFinalizer, Reimburse, Disprove, LatestBlockhash, asserts,
/// OP_RETURN, and the CPFP anchor. Watchtower pairs are extra and deposit-dependent.
fn min_kickoff_output_count() -> usize {
    FIRST_FIVE_OUTPUTS + ClementineBitVMPublicKeys::number_of_assert_txs() + 2
}

/// True if `spending_tx` spends `kickoff_outpoint` as a protocol kickoff.
///
/// Sequence is the first filter: the 1-block CSV burn / UnspentKickoff path
/// cannot be a kickoff. A kickoff spends only that UTXO, so more than one
/// input cannot be a kickoff. After that it must be version 3, have the
/// protocol output count, and include the kickoff OP_RETURN ending in this
/// operator's xonly pk. Missing the spent input is an invariant error: the
/// caller only passes transactions indexed as spending this outpoint.
fn spending_is_protocol_kickoff(
    kickoff_outpoint: OutPoint,
    spending_tx: &Transaction,
    operator_xonly_pk: XOnlyPublicKey,
) -> std::result::Result<bool, BridgeError> {
    let Some(txin) = spending_tx
        .input
        .iter()
        .find(|txin| txin.previous_output == kickoff_outpoint)
    else {
        return Err(eyre!(
            "Spending transaction {} does not include kickoff outpoint {}",
            spending_tx.compute_txid(),
            kickoff_outpoint
        )
        .into());
    };
    if txin.sequence.is_relative_lock_time() {
        return Ok(false);
    }
    if spending_tx.input.len() != 1 {
        return Ok(false);
    }
    if spending_tx.version != NON_STANDARD_V3 {
        return Ok(false);
    }
    if spending_tx.output.len() < min_kickoff_output_count() {
        return Ok(false);
    }
    let operator_pk = operator_xonly_pk.serialize();
    Ok(spending_tx.output.iter().any(|output| {
        parse_op_return_data(&output.script_pubkey)
            .is_some_and(|data| data.len() == 64 && data[32..] == operator_pk)
    }))
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

        RetryIf::spawn(
            strategy,
            || async { self.client.call(cmd, args).await },
            |error: &bitcoincore_rpc::Error| is_retryable_for_command(cmd, error),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::{
        actor::Actor,
        bitvm_client::SECP,
        config::protocol::{ProtocolParamset, REGTEST_PARAMSET},
        extended_bitcoin_rpc::{BitcoinRPCError, ExtendedBitcoinRpc},
        test::common::{citrea, create_regtest_rpc, create_test_config_with_thread_name},
    };
    use bitcoin::{amount, key::Keypair, Address, Amount, FeeRate, XOnlyPublicKey};
    use bitcoincore_rpc::RpcApi;
    use citrea_e2e::{
        bitcoin::DEFAULT_FINALITY_DEPTH,
        config::{BitcoinConfig, TestCaseConfig, TestCaseDockerConfig},
        framework::TestFramework,
        node::NodeKind,
        test_case::{TestCase, TestCaseRunner},
        Result,
    };
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
                    _ => panic!("Unexpected error: {e:?}"),
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
        use std::time::Duration;

        fn rpc_error(code: i32) -> bitcoincore_rpc::Error {
            bitcoincore_rpc::Error::JsonRpc(bitcoincore_rpc::RpcError::Rpc(
                jsonrpc_async::error::RpcError {
                    code,
                    message: "test".to_string(),
                    data: None,
                },
            ))
        }

        #[test]
        fn rpc_errors_are_classified_by_code() {
            let warmup = rpc_error(super::super::RPC_IN_WARMUP_CODE);
            assert!(super::super::is_retryable_for_command(
                "sendtoaddress",
                &warmup
            ));

            let insufficient_funds = rpc_error(-6);
            assert!(!super::super::is_retryable_for_command(
                "getblock",
                &insufficient_funds
            ));

            for code in [
                super::super::RPC_CLIENT_NOT_CONNECTED,
                super::super::RPC_CLIENT_IN_INITIAL_DOWNLOAD,
            ] {
                let error = rpc_error(code);
                assert!(
                    super::super::is_retryable_for_command("getblock", &error),
                    "{code} should be retried for a read-only command"
                );
                assert!(
                    !super::super::is_retryable_for_command("sendtoaddress", &error),
                    "{code} must not retry a wallet-funded command"
                );
            }
        }

        #[test]
        fn unknown_outcomes_never_retry_wallet_mutations() {
            for cmd in [
                "sendtoaddress",
                "sendmany",
                "bumpfee",
                "psbtbumpfee",
                "fundrawtransaction",
                "walletcreatefundedpsbt",
                "lockunspent",
                "generatetoaddress",
                "unknown-future-command",
            ] {
                let error = bitcoincore_rpc::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "test",
                ));
                assert!(
                    !super::super::is_retryable_for_command(cmd, &error),
                    "{cmd} must not be retried after an unknown outcome"
                );
            }

            for cmd in ["getblock", "sendrawtransaction", "submitpackage"] {
                let error = bitcoincore_rpc::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "test",
                ));
                assert!(
                    super::super::is_retryable_for_command(cmd, &error),
                    "{cmd} should be safe to repeat"
                );
            }
        }

        fn transport_error(error: reqwest::Error) -> bitcoincore_rpc::Error {
            bitcoincore_rpc::Error::JsonRpc(bitcoincore_rpc::RpcError::Transport(Box::new(error)))
        }

        #[tokio::test]
        async fn definite_connect_failures_retry_every_command() {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            drop(listener);

            let error = reqwest::Client::new()
                .post(format!("http://{address}"))
                .send()
                .await
                .unwrap_err();
            assert!(error.is_connect());
            assert!(super::super::is_retryable_for_command(
                "sendtoaddress",
                &transport_error(error)
            ));
        }

        async fn decode_error(response: Vec<u8>) -> reqwest::Error {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            use tokio::net::TcpListener;

            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0; 1024];
                assert!(stream.read(&mut request).await.unwrap() > 0);
                stream.write_all(&response).await.unwrap();
            });

            let error = tokio::time::timeout(Duration::from_secs(2), async {
                reqwest::Client::new()
                    .post(format!("http://{address}"))
                    .json(&serde_json::json!({"method": "test", "params": [], "id": 1}))
                    .send()
                    .await
                    .unwrap()
                    .json::<jsonrpc_async::Response>()
                    .await
                    .unwrap_err()
            })
            .await
            .expect("HTTP request timed out");
            server.await.unwrap();
            error
        }

        #[tokio::test]
        async fn decode_errors_distinguish_http_rejections_from_transport_eof() {
            fn http_response(status: &str, body: &str, content_length: usize) -> Vec<u8> {
                format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {content_length}\r\nConnection: close\r\n\r\n{body}"
                )
                .into_bytes()
            }

            for status in ["401 Unauthorized", "404 Not Found"] {
                let rejection = decode_error(http_response(status, "", 0)).await;
                assert!(rejection.is_decode());
                assert!(!super::super::is_transport_eof_decode(&rejection));
                assert!(!super::super::is_retryable_for_command(
                    "getblock",
                    &transport_error(rejection)
                ));
            }

            let partial_body = r#"{"result": {"ok": true}"#;
            let truncated = decode_error(http_response(
                "200 OK",
                partial_body,
                partial_body.len() + 32,
            ))
            .await;
            assert!(super::super::is_transport_eof_decode(&truncated));
            let truncated = transport_error(truncated);
            assert!(super::super::is_retryable_for_command(
                "getblock", &truncated
            ));
            assert!(super::super::is_retryable_for_command(
                "sendrawtransaction",
                &truncated
            ));
            assert!(!super::super::is_retryable_for_command(
                "sendtoaddress",
                &truncated
            ));
        }

        #[test]
        fn connection_drop_io_kinds_are_transport_eof_sources() {
            use std::io::{Error, ErrorKind};

            for kind in [
                ErrorKind::ConnectionReset,
                ErrorKind::ConnectionAborted,
                ErrorKind::BrokenPipe,
                ErrorKind::TimedOut,
                ErrorKind::UnexpectedEof,
            ] {
                assert!(
                    super::super::is_connection_drop_io(&Error::new(kind, "test")),
                    "{kind:?} should be a connection-drop source"
                );
            }
            assert!(!super::super::is_connection_drop_io(&Error::new(
                ErrorKind::InvalidData,
                "test"
            )));
        }
    }

    mod rpc_call_retry_tests {

        use super::*;
        use secrecy::SecretString;
        use std::time::Duration;

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
        }

        #[tokio::test]
        async fn test_rpc_call_retry_with_invalid_host() {
            use crate::extended_bitcoin_rpc::RetryConfig;

            let user = SecretString::new("user".to_string().into());
            let password = SecretString::new("password".to_string().into());
            let invalid_url = "http://nonexistent-host:8332".to_string();
            // Connect failures are retryable; cap attempts so this test does not wait on DNS.
            let retry = RetryConfig::new(10, Duration::from_millis(10), 1, 2, false);

            let res = ExtendedBitcoinRpc::connect(invalid_url, user, password, Some(retry)).await;

            assert!(res.is_err());
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

    /// `nofn` is the test signer so the kickoff finalizer is a CheckSig we can spend.
    fn test_kickoff_tx(
        signer: &Actor,
        round_tx: &crate::builder::transaction::TxHandler,
        kickoff_idx: u32,
        extra_watchtowers: Vec<XOnlyPublicKey>,
        unlock_hashes: Vec<[u8; 20]>,
        paramset: &'static ProtocolParamset,
    ) -> crate::builder::transaction::TxHandler {
        use crate::{
            bitvm_client::ClementineBitVMPublicKeys,
            builder::transaction::{
                create_kickoff_txhandler, create_move_to_vault_txhandler, AssertScripts,
                DisprovePath,
            },
            deposit::{
                Actors, BaseDepositData, DepositData, DepositInfo, DepositType, KickoffData,
                SecurityCouncil,
            },
            operator::RoundIndex,
            EVMAddress,
        };
        use bitcoin::{hashes::Hash, OutPoint, ScriptBuf, Txid};
        use std::str::FromStr;

        let mut deposit_data = DepositData {
            nofn_xonly_pk: Some(signer.xonly_public_key),
            deposit: DepositInfo {
                deposit_outpoint: OutPoint::new(Txid::all_zeros(), 1),
                deposit_type: DepositType::BaseDeposit(BaseDepositData {
                    evm_address: EVMAddress([0u8; 20]),
                    recovery_taproot_address: bitcoin::Address::from_str(
                        "bcrt1p65yp9q9fxtf7dyvthyrx26xxm2czanvrnh9rtvphmlsjvhdt4k6qw4pkss",
                    )
                    .unwrap(),
                }),
            },
            actors: Actors {
                verifiers: vec![],
                watchtowers: extra_watchtowers,
                operators: vec![signer.xonly_public_key],
            },
            security_council: SecurityCouncil {
                pks: vec![signer.xonly_public_key],
                threshold: 1,
            },
        };
        let move_tx = create_move_to_vault_txhandler(&mut deposit_data, paramset).unwrap();
        let assert_hashes = vec![[0u8; 32]; ClementineBitVMPublicKeys::number_of_assert_txs()];
        let disprove_root = [1u8; 32];
        create_kickoff_txhandler(
            KickoffData {
                operator_xonly_pk: signer.xonly_public_key,
                round_idx: RoundIndex::Round(0),
                kickoff_idx,
            },
            round_tx,
            &move_tx,
            &mut deposit_data,
            signer.xonly_public_key,
            AssertScripts::AssertScriptTapNodeHash(&assert_hashes),
            DisprovePath::HiddenNode(&disprove_root),
            ScriptBuf::from_bytes(vec![0x51]).to_bytes(),
            AssertScripts::AssertScriptTapNodeHash(&[[2u8; 32]]),
            &unlock_hashes,
            paramset,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn collateral_check_rejects_leftover_kickoffs_in_passed_round() {
        use crate::{
            actor::WinternitzDerivationPath,
            builder::{
                script::SpendPath,
                transaction::{
                    create_burn_unused_kickoff_connectors_txhandler, create_round_nth_txhandler,
                    input::UtxoVout, output::UnspentTxOut, KickoffWinternitzKeys, TransactionType,
                    TxHandlerBuilder, DEFAULT_SEQUENCE,
                },
            },
            constants::NON_STANDARD_V3,
            database::Database,
            deposit::OperatorData,
            operator::RoundIndex,
            rpc::clementine::NormalSignatureKind,
        };
        use bitcoin::Transaction;

        let mut config = create_test_config_with_thread_name().await;
        config.test_params.mine_0_fee_txs = true;
        let db = Database::new(&config).await.unwrap();
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc();
        let paramset = config.protocol_paramset();

        async fn mine_and_index(db: &Database, rpc: &ExtendedBitcoinRpc) {
            rpc.mine_blocks(1).await.unwrap();
            let height = u32::try_from(rpc.get_block_count().await.unwrap()).unwrap();
            let hash = rpc.get_block_hash(height as u64).await.unwrap();
            let block = rpc.get_block(&hash).await.unwrap();
            let mut dbtx = db.begin_transaction().await.unwrap();
            crate::bitcoin_syncer::save_block(db, &mut dbtx, &block, height)
                .await
                .unwrap();
            dbtx.commit().await.unwrap();
        }
        async fn broadcast(db: &Database, rpc: &ExtendedBitcoinRpc, tx: &Transaction) {
            rpc.send_raw_transaction(tx).await.unwrap();
            mine_and_index(db, rpc).await;
        }

        let signer = Actor::new(
            config.test_params.all_operators_secret_keys[0],
            paramset.network,
        );
        let collateral = rpc
            .send_to_address(&signer.address, paramset.collateral_funding_amount)
            .await
            .unwrap();
        rpc.mine_blocks(1).await.unwrap();

        let mut wpks = Vec::new();
        for round_idx in RoundIndex::iter_rounds(paramset.num_round_txs + 1) {
            for kickoff_idx in 0..paramset.num_kickoffs_per_round {
                wpks.push(
                    signer
                        .derive_winternitz_pk(WinternitzDerivationPath::Kickoff(
                            round_idx,
                            kickoff_idx as u32,
                            paramset,
                        ))
                        .unwrap(),
                );
            }
        }
        let kickoff_wpks = KickoffWinternitzKeys::new(
            wpks,
            paramset.num_kickoffs_per_round,
            paramset.num_round_txs,
        )
        .unwrap();
        let operator_data = OperatorData {
            xonly_pk: signer.xonly_public_key,
            collateral_funding_outpoint: collateral,
            reimburse_addr: signer.address.clone(),
        };

        let (mut round_tx, mut ready_to_reimburse_tx) = create_round_nth_txhandler(
            signer.xonly_public_key,
            collateral,
            paramset.collateral_funding_amount,
            RoundIndex::Round(0),
            &kickoff_wpks,
            paramset,
        )
        .unwrap();

        signer
            .tx_sign_and_fill_sigs(&mut round_tx, &[], None)
            .unwrap();
        broadcast(&db, rpc, round_tx.get_cached_tx()).await;

        assert!(
            rpc.collateral_check(&operator_data, &kickoff_wpks, paramset, &db)
                .await
                .unwrap(),
            "current round with unspent kickoffs should still be accepted"
        );

        signer
            .tx_sign_and_fill_sigs(&mut ready_to_reimburse_tx, &[], None)
            .unwrap();
        broadcast(&db, rpc, ready_to_reimburse_tx.get_cached_tx()).await;

        assert!(
            !rpc.collateral_check(&operator_data, &kickoff_wpks, paramset, &db)
                .await
                .unwrap(),
            "passed round with leftover kickoffs should be rejected"
        );

        let key_out = || {
            UnspentTxOut::from_scripts(
                Amount::ZERO,
                vec![],
                Some(signer.xonly_public_key),
                paramset.network,
            )
        };
        // Winternitz spend of leftover 0 that is not a protocol kickoff.
        let mut dummy_spend = TxHandlerBuilder::new(TransactionType::Kickoff)
            .with_version(NON_STANDARD_V3)
            .add_input(
                NormalSignatureKind::OperatorSighashDefault,
                round_tx.get_spendable_output(UtxoVout::Kickoff(0)).unwrap(),
                SpendPath::ScriptSpend(0),
                DEFAULT_SEQUENCE,
            )
            .add_output(key_out())
            .add_output(key_out())
            .finalize();
        signer
            .tx_sign_winternitz(
                &mut dummy_spend,
                &[(
                    vec![0u8; 20],
                    WinternitzDerivationPath::Kickoff(RoundIndex::Round(0), 0, paramset),
                )],
            )
            .unwrap();
        rpc.send_raw_transaction(dummy_spend.get_cached_tx())
            .await
            .unwrap();

        let mut protocol_kickoff = test_kickoff_tx(&signer, &round_tx, 1, vec![], vec![], paramset);
        signer
            .tx_sign_winternitz(
                &mut protocol_kickoff,
                &[(
                    vec![0u8; 20],
                    WinternitzDerivationPath::Kickoff(RoundIndex::Round(0), 1, paramset),
                )],
            )
            .unwrap();
        rpc.send_raw_transaction(protocol_kickoff.get_cached_tx())
            .await
            .unwrap();

        let unused: Vec<usize> = (2..paramset.num_kickoffs_per_round).collect();
        let mut burn_tx = create_burn_unused_kickoff_connectors_txhandler(
            &round_tx,
            &unused,
            &signer.address,
            paramset,
        )
        .unwrap();
        signer
            .tx_sign_and_fill_sigs(&mut burn_tx, &[], None)
            .unwrap();
        rpc.send_raw_transaction(burn_tx.get_cached_tx())
            .await
            .unwrap();
        mine_and_index(&db, rpc).await;

        assert!(
            !rpc.collateral_check(&operator_data, &kickoff_wpks, paramset, &db)
                .await
                .unwrap(),
            "kickoff in a passed round with unspent finalizer should be rejected"
        );

        let mut spend_finalizer = TxHandlerBuilder::new(TransactionType::Dummy)
            .with_version(NON_STANDARD_V3)
            .add_input(
                NormalSignatureKind::OperatorSighashDefault,
                protocol_kickoff
                    .get_spendable_output(UtxoVout::KickoffFinalizer)
                    .unwrap(),
                SpendPath::ScriptSpend(0),
                DEFAULT_SEQUENCE,
            )
            .add_output(key_out())
            .finalize();
        signer
            .tx_sign_and_fill_sigs(&mut spend_finalizer, &[], None)
            .unwrap();
        broadcast(&db, rpc, spend_finalizer.get_cached_tx()).await;

        assert!(
            rpc.collateral_check(&operator_data, &kickoff_wpks, paramset, &db)
                .await
                .unwrap(),
            "operator should be accepted after leftover kickoffs are burned and the kickoff finalizer is spent"
        );
    }

    /// Locks the classifier to `create_kickoff_txhandler`: a real kickoff, with and
    /// without extra watchtower outputs, must be classified as a protocol kickoff.
    #[test]
    fn create_kickoff_txhandler_is_classified_as_protocol_kickoff() {
        use crate::{
            bitvm_client::UNSPENDABLE_XONLY_PUBKEY,
            builder::transaction::{
                create_round_nth_txhandler, input::UtxoVout, KickoffWinternitzKeys,
            },
            operator::RoundIndex,
        };
        use bitcoin::{
            hashes::Hash, secp256k1::rand::thread_rng, secp256k1::SecretKey, Network, OutPoint,
            Txid,
        };

        let paramset = &REGTEST_PARAMSET;
        let signer = Actor::new(SecretKey::new(&mut thread_rng()), Network::Regtest);
        let wpks = KickoffWinternitzKeys::new(
            vec![
                vec![[0u8; 20]; 43];
                (paramset.num_round_txs + 1) * paramset.num_kickoffs_per_round
            ],
            paramset.num_kickoffs_per_round,
            paramset.num_round_txs,
        )
        .unwrap();
        let (round_tx, _) = create_round_nth_txhandler(
            signer.xonly_public_key,
            OutPoint::new(Txid::all_zeros(), 0),
            paramset.collateral_funding_amount,
            RoundIndex::Round(0),
            &wpks,
            paramset,
        )
        .unwrap();
        let kickoff_outpoint = *round_tx
            .get_spendable_output(UtxoVout::Kickoff(0))
            .unwrap()
            .get_prev_outpoint();

        let classify = |extra_watchtowers: Vec<bitcoin::XOnlyPublicKey>,
                        unlock_hashes: Vec<[u8; 20]>| {
            let kickoff = test_kickoff_tx(
                &signer,
                &round_tx,
                0,
                extra_watchtowers,
                unlock_hashes,
                paramset,
            );
            super::spending_is_protocol_kickoff(
                kickoff_outpoint,
                kickoff.get_cached_tx(),
                signer.xonly_public_key,
            )
            .unwrap()
        };

        assert!(
            classify(vec![], vec![]),
            "create_kickoff_txhandler output with no extra watchtowers must be a protocol kickoff"
        );
        assert!(
            classify(vec![*UNSPENDABLE_XONLY_PUBKEY], vec![[0u8; 20]]),
            "create_kickoff_txhandler output with extra watchtower outputs must still be a protocol kickoff"
        );
    }

    #[test]
    fn spending_is_protocol_kickoff_errors_if_input_is_missing() {
        use bitcoin::hashes::Hash;
        let kickoff_outpoint = bitcoin::OutPoint {
            txid: bitcoin::Txid::all_zeros(),
            vout: 1,
        };
        let spending_tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        let err = super::spending_is_protocol_kickoff(
            kickoff_outpoint,
            &spending_tx,
            *crate::bitvm_client::UNSPENDABLE_XONLY_PUBKEY,
        )
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("does not include kickoff outpoint"));
    }
}
