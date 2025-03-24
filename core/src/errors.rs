//! # Errors
//!
//! This module defines globally shared error messages, the crate-level error wrapper and extension traits for error/results.
//! Our error paradigm is as follows:
//! 1. Modules define their own error types when they need shared error messages. Module-level errors can wrap eyre::Report to capture arbitrary errors.
//! 2. The crate-level error wrapper (BridgeError) is used to wrap errors from modules and attach extra context (ie. which module caused the error).
//! 3. External crate errors are always wrapped by the BridgeError and never by module-level errors.
//! 4. When using external crates inside modules, extension traits are used to convert external-crate errors into BridgeError. This is further wrapped in an eyre::Report to avoid a circular dependency.
//! 5. BridgeError can be converted to tonic::Status to be returned to the client. Module-level errors can define Into<Status> to customize the returned status.
//! 6. BridgeError can be used to share error messages across modules.
//!
//! ## Error wrapper example usage with `TxError`
//! ```rust
//! use thiserror::Error;
//! use crate::errors::{BridgeError, TxError, ErrorExt, ResultExt};
//!
//! // Function with external crate signature
//! pub fn external_crate() -> Result<(), hex::FromHexError> {
//!     Err(hex::FromHexError::InvalidStringLength)
//! }
//!
//! // Internal function failing with some error
//! pub fn internal_function_in_another_module() -> Result<(), BridgeError> {
//!     eyre::bail!("I just failed")
//! }
//!
//!
//! // This function returns module-level errors
//! // It can wrap external crate errors, and other crate-level errors
//! pub fn create_some_txs() -> Result<(), TxError> {
//!     // Do external things
//!     // This wraps the external crate error with BridgeError, then boxes inside an eyre::Report. The `?` will convert the eyre::Report into a TxError.
//!     external_crate().map_to_eyre()?;
//!
//!     // Do internal things
//!     // This will simply wrap in eyre::Report, then rewrap in TxError.
//!     internal_function_in_another_module().map_to_eyre()?;
//!
//!     // Return a module-level error
//!     Err(TxError::TxInputNotFound)
//! }
//!
//! pub fn main() -> Result<(), BridgeError> {
//!     create_some_txs()?;
//!     // This will convert the TxError into a BridgeError, wrapping the error with the message "Failed to build transactions" regardless of the actual error.
//!
//!     // Chain will be:
//!     // 1. External case: BridgeError -> TxError -> eyre::Report -> hex::FromHexError
//!     // 2. Internal case: BridgeError -> TxError -> eyre::Report -> BridgeError -> eyre::Report (this could've been any other module-level error)
//!     // 3. Module-level error: BridgeError -> TxError
//!
//!
//!     // error(transparent) ensures that unnecessary error messages are not repeated.
//! }
//! ```

use crate::{
    builder::transaction::TransactionType, header_chain_prover::HeaderChainProverError,
    tx_sender::SendTxError,
};
use bitcoin::{BlockHash, FeeRate, OutPoint, Txid};
use core::fmt::Debug;
use hex::FromHexError;
use jsonrpsee::types::ErrorObject;
use thiserror::Error;

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
    #[error("BitvmSetupNotFound for operator {0}, deposit_txid {1}")]
    BitvmSetupNotFound(i32, Txid),
    #[error("Transaction input is missing spend info")]
    MissingSpendInfo,

    #[error(transparent)]
    Other(#[from] eyre::Report),
}

/// Errors returned by the bridge.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BridgeError {
    // TODO: migrate
    // State Manager errors
    #[error("State machine received event that it doesn't know how to handle: {0}")]
    UnhandledEvent(String),
    #[error("{0}")]
    Error(String),

    // Module-level errors
    // Header chain prover errors
    #[error("Prover returned an error")]
    Prover(#[from] HeaderChainProverError),
    #[error("Failed to build transactions: {0}")]
    Transaction(#[from] TxError),
    #[error("Failed to send transactions: {0}")]
    SendTx(#[from] SendTxError),

    // Shared error messages
    #[error("Unsupported network")]
    UnsupportedNetwork,
    #[error("Invalid configuration: {0}")]
    ConfigError(String),
    #[error("Environment variable {1}: {0}")]
    EnvVarNotSet(std::env::VarError, &'static str),
    #[error("Environment variable {0} is malformed: {1}")]
    EnvVarMalformed(&'static str, String),

    #[error("Failed to convert between integer types")]
    IntConversionError,
    #[error("Failed to encode/decode data using borsh")]
    BorshError,

    #[error("Operator idx {0} was not found in the DB")]
    OperatorNotFound(u32),
    #[error("User's withdrawal UTXO not set for withdrawal index: {0}")]
    UsersWithdrawalUtxoNotSetForWithdrawalIndex(u32),

    #[error("Blockgazer can't synchronize database with active blockchain; Too deep {0}")]
    BlockgazerTooDeep(u64),

    // RPC errors
    #[error("Can't bump fee for Txid of {0} and feerate of {1}: {2}")]
    BumpFeeError(Txid, FeeRate, String),
    #[error("Cannot bump fee - UTXO is already spent")]
    BumpFeeUTXOSpent(OutPoint),
    #[error("Transaction is already in block: {0}")]
    TransactionAlreadyInBlock(BlockHash),

    // Aggregator errors
    #[error("Sighash stream ended prematurely")]
    SighashStreamEndedPrematurely,
    #[error("{0} input channel for {1} ended prematurely")]
    ChannelEndedPrematurely(&'static str, &'static str),

    // TODO: Couldn't put `from[SendError<T>]` because of generics, find a way
    /// 0: Data name, 1: Error message
    #[error("Error while sending {0} data: {1}")]
    SendError(&'static str, String),

    // External error wrappers
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
    #[error("{0}")]
    TonicStatus(#[from] tonic::Status),

    // Base wrapper for eyre
    #[error(transparent)]
    Eyre(#[from] eyre::Report),
}

pub trait ErrorExt: Sized {
    fn into_eyre(self) -> eyre::Report;
}

pub trait ResultExt: Sized {
    type Output;
    fn map_to_eyre(self) -> Result<Self::Output, eyre::Report>;
}

impl<T: Into<BridgeError>> ErrorExt for T {
    fn into_eyre(self) -> eyre::Report {
        match self.into() {
            BridgeError::Eyre(report) => report,
            other => eyre::eyre!(other),
        }
    }
}

impl<U: Sized, T: Into<BridgeError>> ResultExt for Result<U, T> {
    type Output = U;

    fn map_to_eyre(self) -> Result<Self::Output, eyre::Report> {
        self.map_err(Into::into).map_err(BridgeError::into_eyre)
    }
}

impl From<BridgeError> for ErrorObject<'static> {
    fn from(val: BridgeError) -> Self {
        ErrorObject::owned(-30000, format!("{:?}", val), Some(1))
    }
}

impl From<BridgeError> for tonic::Status {
    fn from(val: BridgeError) -> Self {
        // TODO: we need a better solution for user-facing errors.
        // This exposes our internal errors to the user. What we want here is:
        // 1. We don't want to expose internal errors to the user.
        // 2. We want lower-level errors to be able to define whether and how they want to be exposed to the user.
        tracing::error!(
            "Casting BridgeError to Status message (possibly lossy): {:?}",
            val
        );
        tonic::Status::from_error(Box::new(val))
    }
}
