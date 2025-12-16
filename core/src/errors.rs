//! # Errors
//!
//! This module provides the manual `From<TxError>` implementation for `BridgeError`.
//! Error types are now in the `clementine-errors` crate and should be imported
//! directly from there (e.g., `use clementine_errors::BridgeError;`).
//!
//! This file will be removed once `TxError` is moved to `clementine-errors`.

use clementine_errors::BridgeError;

// Re-export TxError from its original location for backwards compatibility
pub use crate::builder::transaction::TxError;

/// Manual implementation to convert TxError into BridgeError.
///
/// This is implemented manually because `TxError` contains `TransactionType`,
/// a domain-specific type that can't be moved to `clementine-errors` until
/// `clementine-types` crate exists.
impl From<TxError> for BridgeError {
    fn from(err: TxError) -> Self {
        BridgeError::Transaction(eyre::eyre!(err))
    }
}

#[cfg(test)]
mod tests {
    use clementine_errors::{BitcoinRPCError, BridgeError, ErrorExt};
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

        let status: tonic::Status = err.into();
        assert!(status.message().contains("Error A"));
        assert!(status.message().contains("Error B"));
        assert!(status.message().contains("Bitcoin"));
    }

    #[test]
    fn test_tx_error_conversion() {
        let tx_err = TxError::TxInputNotFound;
        let bridge_err: BridgeError = tx_err.into();
        assert!(matches!(bridge_err, BridgeError::Transaction(_)));
    }
}
