//! # Errors
//!
//! This module defines globally shared error messages, the crate-level error wrapper and extension traits for error/results.
//! Our error paradigm is as follows:
//! 1. Modules define their own error types when they need shared error messages. Module-level errors can wrap eyre::Report to capture arbitrary errors.
//! 2. The crate-level error wrapper (BridgeError) is used to wrap errors from modules and attach extra context (ie. which module caused the error).
//! 3. External crate errors are always wrapped by the BridgeError and never by module-level errors.
//! 4. When using external crates inside modules, extension traits are used to convert external-crate errors into BridgeError. This is further wrapped in an eyre::Report to avoid a circular dependency.
//! 5. BridgeError can be converted to tonic::Status to be returned to the client. Module-level errors can define [`Into<Status>`] to customize the returned status.
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
};
#[cfg(feature = "automation")]
use crate::{states::StateMachineError, tx_sender::SendTxError};
use bitcoin::{secp256k1::PublicKey, OutPoint, Txid, XOnlyPublicKey};
use clap::builder::StyledStr;
use core::fmt::Debug;
use hex::FromHexError;
use thiserror::Error;
use tonic::Status;

pub use crate::builder::transaction::TxError;

/// Errors returned by the bridge.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BridgeError {
    #[error("Header chain prover returned an error: {0}")]
    Prover(#[from] HeaderChainProverError),
    #[error("Failed to build transactions: {0}")]
    Transaction(#[from] TxError),
    #[cfg(feature = "automation")]
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
    #[cfg(feature = "automation")]
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
    #[error(transparent)]
    RPC(#[from] Status),

    #[error("Arithmetic overflow occurred: {0}")]
    ArithmeticOverflow(&'static str),
    #[error("Insufficient funds: {0}")]
    InsufficientFunds(&'static str),

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

impl From<BridgeError> for tonic::Status {
    fn from(val: BridgeError) -> Self {
        let eyre_report = val.into_eyre();

        // eyre::Report can cast any error in the chain to a Status, so we use its downcast method to get the first Status.
        eyre_report.downcast::<Status>().unwrap_or_else(|report| {
            // We don't want this case to happen, all casts to Status should contain a Status that contains a user-facing error message.
            tracing::error!(
                "Returning internal error on RPC call, full error: {:?}",
                report
            );

            let mut status = tonic::Status::internal(report.to_string());
            status.set_source(Into::into(
                Into::<Box<dyn std::error::Error + Send + Sync>>::into(report),
            ));
            status
        })
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

    #[test]
    fn test_status_in_chain_cast_properly() {
        let err: BridgeError = eyre::eyre!("Some problem")
            .wrap_err(tonic::Status::deadline_exceeded("Some timer expired"))
            .wrap_err("Something else went wrong")
            .into();

        let status: Status = err.into_status();
        assert_eq!(status.code(), tonic::Code::DeadlineExceeded);
        assert_eq!(status.message(), "Some timer expired");
    }
}
