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
//! 7. When the error cause is not sufficiently explained by the error messages, use `eyre::Context::wrap_err` to add more context. This will not hinder modules that are trying to match the error.
//!
//! ## Error wrapper example usage with `TxError`
//! ```rust
//! use thiserror::Error;
//! use clementine_core::errors::{BridgeError, TxError, ErrorExt, ResultExt};
//!
//! // Function with external crate signature
//! pub fn external_crate() -> Result<(), hex::FromHexError> {
//!     Err(hex::FromHexError::InvalidStringLength)
//! }
//!
//! // Internal function failing with some error
//! pub fn internal_function_in_another_module() -> Result<(), BridgeError> {
//!     Err(eyre::eyre!("I just failed").into())
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
//! pub fn test() -> Result<(), BridgeError> {
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
//!     Ok(())
//! }
//!
//! pub fn main() {
//!     assert!(test().is_err());
//! }
//! ```

use crate::{
    actor::VerificationError,
    builder::transaction::input::SpendableTxInError,
    extended_rpc::BitcoinRPCError,
    header_chain_prover::HeaderChainProverError,
    rpc::{aggregator::AggregatorError, ParserError},
    states::StateMachineError,
    tx_sender::SendTxError,
};
use bitcoin::{secp256k1::PublicKey, OutPoint, XOnlyPublicKey};
use clap::builder::StyledStr;
use core::fmt::Debug;
use hex::FromHexError;
use thiserror::Error;

pub use crate::builder::transaction::TxError;

/// Errors returned by the bridge.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BridgeError {
    // TODO: migrate
    #[error("Uncategorized error: {0}")]
    Error(String),

    // Module-level errors
    // Header chain prover errors
    #[error("Prover returned an error: {0}")]
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
    #[error("Deposit is invalid")]
    InvalidDeposit,
    #[error("Operator data mismatch. Data already stored in BD and received by set_operator doesn't match for xonly_pk: {0}")]
    OperatorDataMismatch(XOnlyPublicKey),

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
    #[error("{0}")]
    CLIDisplayAndExit(StyledStr),

    // Base wrapper for eyre
    #[error(transparent)]
    Eyre(#[from] eyre::Report),
}

/// Extension traits for errors to easily convert them to eyre::Report and
/// tonic::Status through BridgeError.
pub trait ErrorExt: Sized {
    /// Converts the error into an eyre::Report, first wrapping in
    /// BridgeError if necessary. It does not rewrap in eyre::Report if
    /// the given error is already an eyre::Report.
    fn into_eyre(self) -> eyre::Report;
    /// Converts the error into a tonic::Status. Currently defaults to
    /// tonic::Status::from_error which will walk the error chain and attempt to
    /// find a [`tonic::Status`] in the chain. If it can't find one, it will
    /// return an Status::unknown with the Display representation of the error.
    ///
    /// TODO: We should change the implementation to walk the chain of errors
    /// and return the first [`TryInto<tonic::Status>`] error. This is
    /// impossible to do dynamically, each error must be included in the match
    /// arms of the conversion logic.
    fn into_status(self) -> tonic::Status;
}

/// Extension traits for results to easily convert them to eyre::Report and
/// tonic::Status through BridgeError.
pub trait ResultExt: Sized {
    type Output;

    fn map_to_eyre(self) -> Result<Self::Output, eyre::Report>;
    fn map_to_status(self) -> Result<Self::Output, Box<tonic::Status>>;
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

    fn map_to_status(self) -> Result<Self::Output, Box<tonic::Status>> {
        Ok(self.map_err(ErrorExt::into_status)?)
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

        // Possible future implementation, requires manually matching all TryInto<Status> types
        // for err in val.into_eyre().chain() {
        //     match err.downcast_ref::<BridgeError>() {
        //         Some(BridgeError::Aggregator(err)) => {
        //             if let Ok(status) = err.try_into() {
        //                 return status;
        //             }
        //         }
        //         Some(_) | None => {}
        //     }
        // }

        // tracing::error!("Internal server error: {:?}", val);
        // tonic::Status::internal("Internal server error.")
    }
}

#[cfg(test)]
mod tests {
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
                .unwrap()
                .to_string(),
            BridgeError::IntConversionError.to_string()
        );
    }
}
