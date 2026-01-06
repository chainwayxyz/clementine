//! # Clementine Errors
//!
//! This crate defines globally shared error types, the main error wrapper ([`BridgeError`]),
//! and extension traits for error/result conversion.
//!
//! ## Error Hierarchy
//!
//! The crate provides a two-level error hierarchy:
//!
//! 1. **Domain-specific errors** - Errors for specific subsystems (e.g., [`BitcoinRPCError`],
//!    [`AggregatorError`], [`ParserError`]). These can wrap `eyre::Report` to capture arbitrary errors.
//!
//! 2. **[`BridgeError`]** - The main error wrapper that:
//!    - Wraps domain-specific errors with additional context
//!    - Wraps external crate errors directly
//!    - Provides shared error variants used across the codebase
//!    - Converts to [`tonic::Status`] for gRPC responses
//!
//! ## Design Principles
//!
//! 1. Domain-specific errors define their own error types when they need shared error messages.
//! 2. [`BridgeError`] wraps domain errors and attaches extra context (e.g., which subsystem caused the error).
//! 3. External crate errors are always wrapped by [`BridgeError`], never by domain-specific errors.
//! 4. Extension traits ([`ErrorExt`], [`ResultExt`]) convert errors into `eyre::Report` via [`BridgeError`].
//! 5. [`BridgeError`] converts to [`tonic::Status`] for client responses. Domain errors can implement
//!    [`Into<Status>`] to customize the returned status.
//! 6. Use `eyre::Context::wrap_err` to add context without hindering error matching.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use clementine_errors::{BridgeError, ErrorExt, ResultExt};
//!
//! // External crate function
//! fn external_crate() -> Result<(), hex::FromHexError> {
//!     Err(hex::FromHexError::InvalidStringLength)
//! }
//!
//! // Internal function
//! fn internal_function() -> Result<(), BridgeError> {
//!     Err(eyre::eyre!("I just failed").into())
//! }
//!
//! // Convert external errors to eyre::Report via BridgeError
//! fn example() -> Result<(), eyre::Report> {
//!     external_crate().map_to_eyre()?;
//!     internal_function().map_to_eyre()?;
//!     Ok(())
//! }
//! ```

use bitcoin::{secp256k1::PublicKey, BlockHash, FeeRate, OutPoint, Txid, XOnlyPublicKey};
use core::fmt::Debug;
use hex::FromHexError;
use http::StatusCode;
use thiserror::Error;
use tonic::Status;

// Re-export primitives for downstream crates
pub use clementine_primitives::{RoundIndex, TransactionType};

// ============================================================================
// Module-level errors
// ============================================================================

/// Errors from the aggregator module.
#[derive(Debug, Error)]
pub enum AggregatorError {
    #[error("Failed to receive from {stream_name} stream.")]
    InputStreamEndedEarlyUnknownSize { stream_name: String },
    #[error("Failed to send to {stream_name} stream.")]
    OutputStreamEndedEarly { stream_name: String },
    #[error("Failed to send request to {request_name} stream.")]
    RequestFailed { request_name: String },
}

/// RPC parsing errors.
#[derive(Debug, Clone, Error)]
pub enum ParserError {
    #[error("RPC function field {0} is required")]
    RPCRequiredParam(&'static str),
    #[error("RPC function parameter {0} is malformed")]
    RPCParamMalformed(String),
    #[error("RPC function parameter {0} is oversized: {1}")]
    RPCParamOversized(String, usize),
}

impl From<ParserError> for tonic::Status {
    fn from(value: ParserError) -> Self {
        match value {
            ParserError::RPCRequiredParam(field) => {
                Status::invalid_argument(format!("RPC function field {field} is required."))
            }
            ParserError::RPCParamMalformed(field) => {
                Status::invalid_argument(format!("RPC function parameter {field} is malformed."))
            }
            ParserError::RPCParamOversized(field, size) => Status::invalid_argument(format!(
                "RPC function parameter {field} is oversized: {size}",
            )),
        }
    }
}

/// Errors that can occur during Bitcoin RPC operations.
#[derive(Debug, Error)]
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

/// Errors from the header chain prover.
#[derive(Debug, Error)]
pub enum HeaderChainProverError {
    #[error("Error while de/serializing object")]
    ProverDeSerializationError,
    #[error("Wait for candidate batch to be ready")]
    BatchNotReady,
    #[error("Header chain prover not initialized due to config")]
    HeaderChainProverNotInitialized,
    #[error("Unsupported network")]
    UnsupportedNetwork,

    #[error(transparent)]
    Other(#[from] eyre::Report),
}

/// Error type for spendable input construction and validation.
#[derive(Clone, Debug, Error, PartialEq)]
pub enum SpendableTxInError {
    #[error(
        "The taproot spend info contains an incomplete merkle proof map. Some scripts are missing."
    )]
    IncompleteMerkleProofMap,

    #[error("The script_pubkey of the previous output does not match the expected script_pubkey for the taproot spending information.")]
    IncorrectScriptPubkey,

    #[error("Error creating a spendable txin: {0}")]
    Error(String),
}

/// Signature verification errors.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Error)]
pub enum VerificationError {
    #[error("Invalid hex")]
    InvalidHex,
    #[error("Invalid length")]
    InvalidLength,
    #[error("Invalid signature")]
    InvalidSignature,
}

/// Transaction sending errors.
#[derive(Debug, Error)]
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

/// State machine errors.
#[derive(Debug, Error)]
pub enum StateMachineError {
    #[error("State machine received event that it doesn't know how to handle: {0}")]
    UnhandledEvent(String),

    #[error(transparent)]
    Other(#[from] eyre::Report),
}

/// Fee estimation errors.
#[derive(Debug, Error)]
pub enum FeeErr {
    #[error("request timed out")]
    Timeout,
    #[error("transport/decode error: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("http status {0}")]
    Status(StatusCode),
    #[error("json decode error: {0}")]
    JsonDecode(reqwest::Error),
    #[error("'fastestFee' field not found or invalid in API response")]
    MissingField,
}

// ============================================================================
// Transaction Error
// ============================================================================

/// Errors that can occur during transaction construction.
#[derive(Debug, Error)]
pub enum TxError {
    /// TxInputNotFound is returned when the input is not found in the transaction
    #[error("Could not find input of transaction")]
    TxInputNotFound,
    #[error("Could not find output of transaction")]
    TxOutputNotFound,
    #[error("Attempted to set witness when it's already set")]
    WitnessAlreadySet,
    #[error("Script with index {0} not found for transaction")]
    ScriptNotFound(usize),
    #[error("Insufficient Context data for the requested TxHandler")]
    InsufficientContext,
    #[error("No scripts in TxHandler for the TxIn with index {0}")]
    NoScriptsForTxIn(usize),
    #[error("No script in TxHandler for the index {0}")]
    NoScriptAtIndex(usize),
    #[error("Spend Path in SpentTxIn in TxHandler not specified")]
    SpendPathNotSpecified,
    #[error("Actor does not own the key needed in P2TR keypath")]
    NotOwnKeyPath,
    #[error("public key of Checksig in script is not owned by Actor")]
    NotOwnedScriptPath,
    #[error("Couldn't find needed signature from database for tx: {:?}", _0)]
    SignatureNotFound(TransactionType),
    #[error("Couldn't find needed txhandler during creation for tx: {:?}", _0)]
    TxHandlerNotFound(TransactionType),
    #[error("BitvmSetupNotFound for operator {0:?}, deposit_txid {1}")]
    BitvmSetupNotFound(XOnlyPublicKey, Txid),
    #[error("Transaction input is missing spend info")]
    MissingSpendInfo,
    #[error("Incorrect watchtower challenge data length")]
    IncorrectWatchtowerChallengeDataLength,
    #[error("Latest blockhash script must be a single script")]
    LatestBlockhashScriptNumber,
    #[error("Round index cannot be used to create a Round transaction: {0:?}")]
    InvalidRoundIndex(RoundIndex),
    #[error("Index overflow")]
    IndexOverflow,
    #[error("Kickoff winternitz keys in DB has wrong size compared to paramset")]
    KickoffWinternitzKeysDBInconsistency,

    #[error(transparent)]
    Other(#[from] eyre::Report),
}

// ============================================================================
// Bridge Error - Main crate-level error wrapper
// ============================================================================

/// Errors returned by the bridge.
///
/// This is the crate-level error wrapper that wraps errors from modules and
/// attaches extra context (e.g., which module caused the error).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BridgeError {
    #[error("Header chain prover returned an error: {0}")]
    Prover(#[from] HeaderChainProverError),
    #[error("Failed to build transactions: {0}")]
    Transaction(#[from] TxError),
    #[error("Failed to send transactions: {0}")]
    SendTx(#[from] SendTxError),
    #[error("Aggregator error: {0}")]
    Aggregator(#[from] AggregatorError),
    #[error("Failed to parse request: {0}")]
    Parser(#[from] ParserError),
    #[error("SpendableTxIn error: {0}")]
    SpendableTxIn(#[from] SpendableTxInError),
    #[error("Bitcoin RPC error: {0}")]
    BitcoinRPC(#[from] BitcoinRPCError),
    #[error("State machine error: {0}")]
    StateMachine(#[from] StateMachineError),
    #[error("RPC authentication error: {0}")]
    RPCAuthError(#[from] VerificationError),

    // Shared error messages
    #[error("Unsupported network")]
    UnsupportedNetwork,
    #[error("Invalid configuration: {0}")]
    ConfigError(String),
    #[error("Missing environment variable {1}: {0}")]
    EnvVarNotSet(std::env::VarError, &'static str),
    #[error("Environment variable {0} is malformed: {1}")]
    EnvVarMalformed(&'static str, String),

    #[error("Failed to convert between integer types")]
    IntConversionError,
    #[error("Failed to encode/decode data using borsh")]
    BorshError,
    #[error("Operator x-only public key {0} was not found in the DB")]
    OperatorNotFound(XOnlyPublicKey),
    #[error("Verifier with public key {0} was not found among the verifier clients")]
    VerifierNotFound(PublicKey),
    #[error("Deposit not found in DB: {0:?}")]
    DepositNotFound(OutPoint),
    #[error("Deposit is invalid due to {0}")]
    InvalidDeposit(String),
    #[error("Operator data mismatch. Data already stored in DB and received by set_operator doesn't match for xonly_pk: {0}")]
    OperatorDataMismatch(XOnlyPublicKey),
    #[error("Deposit data mismatch. Data already stored in DB doesn't match the new data for deposit {0:?}")]
    DepositDataMismatch(OutPoint),
    #[error("Operator winternitz public keys mismatch. Data already stored in DB doesn't match the new data for operator {0}")]
    OperatorWinternitzPublicKeysMismatch(XOnlyPublicKey),
    #[error("BitVM setup data mismatch. Data already stored in DB doesn't match the new data for operator {0} and deposit {1:?}")]
    BitvmSetupDataMismatch(XOnlyPublicKey, OutPoint),
    #[error("BitVM replacement data will exhaust memory. The maximum number of operations is {0}")]
    BitvmReplacementResourceExhaustion(usize),
    #[error("Operator challenge ack hashes mismatch. Data already stored in DB doesn't match the new data for operator {0} and deposit {1:?}")]
    OperatorChallengeAckHashesMismatch(XOnlyPublicKey, OutPoint),
    #[error("Invalid BitVM public keys")]
    InvalidBitVMPublicKeys,
    #[error("Invalid challenge ack hashes")]
    InvalidChallengeAckHashes,
    #[error("Invalid operator index")]
    InvalidOperatorIndex,
    #[error("Invalid protocol paramset")]
    InvalidProtocolParamset,
    #[error("Deposit already signed and move txid {0} is in chain")]
    DepositAlreadySigned(Txid),
    #[error("Invalid withdrawal ECDSA verification signature")]
    InvalidECDSAVerificationSignature,
    #[error("Withdrawal ECDSA verification signature missing")]
    ECDSAVerificationSignatureMissing,
    #[error("Clementine versions or configs are not compatible: {0}")]
    ClementineNotCompatible(String),

    // External crate error wrappers
    #[error("Failed to call database: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Failed to convert hex string: {0}")]
    FromHexError(#[from] FromHexError),
    #[error("Failed to convert to hash from slice: {0}")]
    FromSliceError(#[from] bitcoin::hashes::FromSliceError),
    #[error("Error while calling EVM contract: {0}")]
    AlloyContract(#[from] alloy::contract::Error),
    #[error("Error while calling EVM RPC function: {0}")]
    AlloyRpc(#[from] alloy::transports::RpcError<alloy::transports::TransportErrorKind>),
    #[error("Error while encoding/decoding EVM type: {0}")]
    AlloySolTypes(#[from] alloy::sol_types::Error),
    #[error(transparent)]
    RPCStatus(#[from] Box<Status>),

    #[error("Arithmetic overflow occurred: {0}")]
    ArithmeticOverflow(&'static str),
    #[error("Insufficient funds: {0}")]
    InsufficientFunds(&'static str),

    // Base wrapper for eyre
    #[error(transparent)]
    Eyre(#[from] eyre::Report),
}

// ============================================================================
// Conversions
// ============================================================================

impl From<Status> for BridgeError {
    fn from(status: Status) -> Self {
        BridgeError::RPCStatus(Box::new(status))
    }
}

impl From<BridgeError> for tonic::Status {
    fn from(val: BridgeError) -> Self {
        let err = format!("{val:#}");
        // delete escape characters
        let flattened = err
            .replace("\\n", " ") // remove escaped newlines
            .replace("\n", " ") // remove real newlines
            .replace("\"", "") // delete quotes
            .replace("\\", ""); // remove any remaining backslashes
        let whitespace_removed = flattened.split_whitespace().collect::<Vec<_>>().join(" ");
        tonic::Status::internal(whitespace_removed)
    }
}

// ============================================================================
// Extension traits
// ============================================================================

/// Extension trait for errors to easily convert them to eyre::Report and
/// tonic::Status through BridgeError.
pub trait ErrorExt: Sized {
    /// Converts the error into an eyre::Report, first wrapping in
    /// BridgeError if necessary. It does not rewrap in eyre::Report if
    /// the given error is already an eyre::Report.
    fn into_eyre(self) -> eyre::Report;
    /// Converts the error into a tonic::Status. Walks the chain of errors and
    /// returns the first [`tonic::Status`] error. If it can't find one, it will
    /// return an Status::internal with the Display representation of the error.
    fn into_status(self) -> tonic::Status;
}

/// Extension trait for results to easily convert them to eyre::Report and
/// tonic::Status through BridgeError.
pub trait ResultExt: Sized {
    type Output;

    fn map_to_eyre(self) -> Result<Self::Output, eyre::Report>;
    #[allow(clippy::result_large_err)]
    fn map_to_status(self) -> Result<Self::Output, tonic::Status>;
}

impl<T: Into<BridgeError>> ErrorExt for T {
    fn into_eyre(self) -> eyre::Report {
        match self.into() {
            BridgeError::Eyre(report) => report,
            other => eyre::eyre!(other),
        }
    }
    fn into_status(self) -> tonic::Status {
        self.into().into()
    }
}

impl<U: Sized, T: Into<BridgeError>> ResultExt for Result<U, T> {
    type Output = U;

    fn map_to_eyre(self) -> Result<Self::Output, eyre::Report> {
        self.map_err(ErrorExt::into_eyre)
    }

    fn map_to_status(self) -> Result<Self::Output, tonic::Status> {
        self.map_err(ErrorExt::into_status)
    }
}

#[cfg(test)]
mod tests {
    use eyre::Context;

    use super::*;

    #[test]
    fn test_downcast() {
        assert_eq!(
            BridgeError::IntConversionError
                .into_eyre()
                .wrap_err("Some other error")
                .into_eyre()
                .wrap_err("some other")
                .downcast_ref::<BridgeError>()
                .expect("should downcast")
                .to_string(),
            BridgeError::IntConversionError.to_string()
        );
    }

    #[test]
    fn test_status_shows_all_errors_in_chain() {
        let err: BridgeError = Err::<(), BridgeError>(BridgeError::BitcoinRPC(
            BitcoinRPCError::TransactionNotConfirmed,
        ))
        .wrap_err(tonic::Status::deadline_exceeded("Error A"))
        .wrap_err("Error B")
        .expect_err("should be error")
        .into();

        let status: Status = err.into();
        assert!(status.message().contains("Error A"));
        assert!(status.message().contains("Error B"));
        assert!(status.message().contains("Bitcoin"));
    }
}
