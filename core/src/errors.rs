//! # Errors
//!
//! This module defines errors, returned by the library.

use crate::builder::transaction::TransactionType;
use bitcoin::{BlockHash, FeeRate, OutPoint, Txid};
use core::fmt::Debug;
use hex::FromHexError;
use jsonrpsee::types::ErrorObject;
use thiserror::Error;

/// Errors returned by the bridge.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BridgeError {
    // RPC errors
    #[error("RPC function field {0} is required!")]
    RPCRequiredParam(&'static str),
    #[error("RPC function parameter {0} is malformed: {1}")]
    RPCParamMalformed(String, String),
    #[error("RPC stream ended unexpectedly: {0}")]
    RPCStreamEndedUnexpectedly(String),
    #[error("Failed to send broadcast message in internal stream: {0}")]
    RPCBroadcastSendError(String),
    /// ConfigError is returned when the configuration is invalid
    #[error("Invalid configuration: {0}")]
    ConfigError(String),
    #[error("Operator idx {0} was not found in the DB")]
    OperatorNotFound(u32),

    // State Manager errors
    #[error("State machine received event that it doesn't know how to handle: {0}")]
    UnhandledEvent(String),

    // Header chain prover errors
    #[error("Prover returned an error: {0}")]
    ProverError(String),
    #[error("Error while de/serializing object: {0}")]
    ProverDeSerializationError(std::io::Error),
    #[error("Blockgazer can't synchronize database with active blockchain; Too deep {0}")]
    BlockgazerTooDeep(u64),
    #[error("No header chain proofs for hash {0}")]
    NoHeaderChainProof(BlockHash),

    #[error("ConversionError: {0}")]
    ConversionError(String),

    #[error("ERROR: {0}")]
    Error(String),

    #[error("Can't encode/decode data using borsh: {0}")]
    BorshError(std::io::Error),

    // TxHandler errors
    /// TxInputNotFound is returned when the input is not found in the transaction
    #[error("TxInputNotFound")]
    TxInputNotFound,
    #[error("TxOutputNotFound")]
    TxOutputNotFound,
    #[error("WitnessAlreadySet")]
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
    #[error("MissingSpendInfo")]
    MissingSpendInfo,

    // TxSender errors
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

    // Wrappers
    #[error("DatabaseError: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("FromHexError: {0}")]
    FromHexError(#[from] FromHexError),
    #[error("FromSliceError: {0}")]
    FromSliceError(#[from] bitcoin::hashes::FromSliceError),

    // Base wrapper for eyre
    #[error("{0:?}")]
    Eyre(#[from] eyre::Report),
}

impl BridgeError {
    #[track_caller]
    pub fn into_eyre(self) -> eyre::Report {
        match self {
            BridgeError::Eyre(report) => report,
            _ => eyre::Report::new(self),
        }
    }
}

impl From<BridgeError> for ErrorObject<'static> {
    fn from(val: BridgeError) -> Self {
        ErrorObject::owned(-30000, format!("{:?}", val), Some(1))
    }
}

impl From<BridgeError> for tonic::Status {
    fn from(val: BridgeError) -> Self {
        tonic::Status::from_error(Box::new(val))
    }
}

impl<T> From<tokio::sync::broadcast::error::SendError<T>> for BridgeError {
    fn from(e: tokio::sync::broadcast::error::SendError<T>) -> Self {
        BridgeError::RPCBroadcastSendError(e.to_string())
    }
}
