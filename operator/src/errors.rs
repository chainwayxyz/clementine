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
