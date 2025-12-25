//! Retry configuration and error handling for RPC calls.

use clementine_errors::BitcoinRPCError;
use std::iter::Take;
use std::sync::Arc;
use std::time::Duration;
use tokio_retry::strategy::{jitter, ExponentialBackoff};

/// Maximum retry attempts to prevent infinite loops.
const MAX_RETRY_ATTEMPTS: usize = 50;

/// Configuration for retry behavior with exponential backoff.
#[derive(Clone)]
pub struct RetryConfig {
    /// Initial delay in milliseconds before first retry.
    pub initial_delay_millis: u64,
    /// Maximum delay between retries.
    pub max_delay: Duration,
    /// Maximum number of retry attempts.
    pub max_attempts: usize,
    /// Backoff multiplier for exponential growth.
    pub backoff_multiplier: u64,
    /// Whether to add jitter to retry delays.
    pub is_jitter: bool,
    /// Pre-computed base strategy for efficiency.
    base_strategy: Arc<Take<ExponentialBackoff>>,
}

impl RetryConfig {
    /// Creates a new retry configuration.
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

    /// Returns a fresh iterator over retry delays.
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

/// Trait to determine if an error is retryable.
pub trait RetryableError {
    /// Returns true if the operation should be retried for this error.
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
