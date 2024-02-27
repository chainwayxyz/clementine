//! This module defines errors returned by the library.
use core::fmt::Debug;
use thiserror::Error;

/// Errors returned by the bridge
#[derive(Clone, Debug, Eq, PartialEq, Error)]
#[non_exhaustive]
pub enum BridgeError {
    #[error("OperatorPendingDeposit")]
    OperatorPendingDeposit,
    #[error("InvalidPeriod")]
    InvalidPeriod,
    #[error("Error")]
    Error,
    /// Returned when the secp256k1 crate returns an error
    #[error("Secpk256Error")]
    Secpk256Error,
    /// Returned when the bitcoin crate returns an error in the sighash module
    #[error("BitcoinSighashError")]
    BitcoinSighashError,
    /// Returned when a non finalized deposit request is found
    #[error("DepositNotFinalized")]
    DepositNotFinalized,
    /// Returned when an invalid deposit UTXO is found
    #[error("InvalidDepositUTXO")]
    InvalidDepositUTXO,
    /// Returned when a UTXO is already spent
    #[error("UTXOSpent")]
    UTXOSpent,
    /// Returned when it fails to get FailedToGetPresigns
    #[error("FailedToGetPresigns")]
    FailedToGetPresigns,
    /// Returned when it fails to find the txid in the block
    #[error("TxidNotFound")]
    TxidNotFound,
    /// Returned in RPC error
    #[error("RpcError")]
    RpcError,
    /// Returned if there is no confirmation data
    #[error("NoConfirmationData")]
    NoConfirmationData,
    /// For Vec<u8> conversion
    #[error("VecConversionError")]
    VecConversionError,
}

impl From<secp256k1::Error> for BridgeError {
    fn from(error: secp256k1::Error) -> Self {
        match error {
            // You can match on different errors if needed and convert accordingly
            _ => BridgeError::Secpk256Error,
        }
    }
}

impl From<bitcoin::sighash::Error> for BridgeError {
    fn from(error: bitcoin::sighash::Error) -> Self {
        match error {
            // You can match on different errors if needed and convert accordingly
            _ => BridgeError::BitcoinSighashError,
        }
    }
}

// bitcoincore_rpc::Error
impl From<bitcoincore_rpc::Error> for BridgeError {
    fn from(error: bitcoincore_rpc::Error) -> Self {
        match error {
            // You can match on different errors if needed and convert accordingly
            _ => BridgeError::RpcError,
        }
    }
}

// Vec<u8>
impl From<Vec<u8>> for BridgeError {
    fn from(_error: Vec<u8>) -> Self {
        BridgeError::VecConversionError
    }
}
