//! This module defines errors returned by the library.
use bitcoin::{
    merkle_tree::MerkleBlockError,
    taproot::{TaprootBuilder, TaprootBuilderError},
};
use core::fmt::Debug;
use std::array::TryFromSliceError;
use thiserror::Error;

/// Errors related to periods
#[derive(Debug, Error)]
pub enum InvalidPeriodError {
    #[error("DepositPeriodMismatch")]
    WithdrawalPeriodMismatch,
    #[error("DepositPeriodMismatch")]
    PreimageRevealPeriodMismatch,
    #[error("DepositPeriodMismatch")]
    InscriptionPeriodMismatch,
}
/// Errors returned by the bridge
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BridgeError {
    /// Returned when the period is invalid
    #[error("InvalidPeriod")]
    InvalidPeriod(InvalidPeriodError),
    /// Returned when the secp256k1 crate returns an error
    #[error("Secpk256Error: {0}")]
    Secpk256Error(secp256k1::Error),
    /// Returned when the bitcoin crate returns an error in the sighash module
    #[error("BitcoinSighashError: {0}")]
    BitcoinSighashError(bitcoin::sighash::Error),
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
    #[error("BitcoinCoreRPCError: {0}")]
    BitcoinRpcError(bitcoincore_rpc::Error),
    /// Returned if there is no confirmation data
    #[error("NoConfirmationData")]
    NoConfirmationData,
    /// For Vec<u8> conversion
    #[error("VecConversionError")]
    VecConversionError,
    /// For TryFromSliceError
    #[error("TryFromSliceError")]
    TryFromSliceError,
    /// Returned when bitcoin::Transaction error happens, also returns the error
    #[error("BitcoinTransactionError")]
    BitcoinTransactionError,
    /// TxInputNotFound is returned when the input is not found in the transaction
    #[error("TxInputNotFound")]
    TxInputNotFound,
    /// PreimageNotFound is returned when the preimage is not found in the the connector tree or claim proof
    #[error("PreimageNotFound")]
    PreimageNotFound,
    /// TaprootBuilderError is returned when the taproot builder returns an error
    /// Errors if the leaves are not provided in DFS walk order
    #[error("TaprootBuilderError")]
    TaprootBuilderError,
    #[error("TaprootScriptError")]
    TaprootScriptError,
    /// ControlBlockError is returned when the control block is not found
    #[error("ControlBlockError")]
    ControlBlockError,
    /// PkSkLengthMismatch is returned when the public key and secret key length do not match
    #[error("PkSkLengthMismatch")]
    PkSkLengthMismatch,
    /// PublicKeyNotFound is returned when the public key is not found in all public keys
    #[error("PublicKeyNotFound")]
    PublicKeyNotFound,
    /// InvalidOperatorKey
    #[error("InvalidOperatorKey")]
    InvalidOperatorKey,
    /// AlreadyInitialized is returned when the operator is already initialized
    #[error("AlreadyInitialized")]
    AlreadyInitialized,
    /// Blockhash not found
    #[error("Blockhash not found")]
    BlockhashNotFound,
    /// Block not found
    #[error("Block not found")]
    BlockNotFound,
    /// Merkle Block Error
    #[error("MerkleBlockError: {0}")]
    MerkleBlockError(MerkleBlockError),
    /// Merkle Proof Error
    #[error("MerkleProofError")]
    MerkleProofError,
    /// JSON RPC Error
    /// Returned when the JSON RPC call fails
    #[error("JsonRpcError: {0}")]
    JsonRpcError(jsonrpsee::core::Error),
    /// Given key pair is invalid and new pairs can't be generated randomly
    #[error("InvalidKeyPair")]
    InvalidKeyPair,
}

impl From<secp256k1::Error> for BridgeError {
    fn from(err: secp256k1::Error) -> Self {
        BridgeError::Secpk256Error(err)
    }
}

impl From<bitcoin::sighash::Error> for BridgeError {
    fn from(err: bitcoin::sighash::Error) -> Self {
        BridgeError::BitcoinSighashError(err)
    }
}
// Vec<u8>
impl From<Vec<u8>> for BridgeError {
    fn from(_error: Vec<u8>) -> Self {
        BridgeError::VecConversionError
    }
}

impl From<TryFromSliceError> for BridgeError {
    fn from(_error: TryFromSliceError) -> Self {
        // Here, you can choose the appropriate variant of BridgeError that corresponds
        // to a TryFromSliceError, or add a new variant to BridgeError if necessary.
        BridgeError::TryFromSliceError
    }
}

impl From<bitcoin::Transaction> for BridgeError {
    fn from(_error: bitcoin::Transaction) -> Self {
        BridgeError::BitcoinTransactionError
    }
}

impl From<TaprootBuilderError> for BridgeError {
    fn from(_error: TaprootBuilderError) -> Self {
        BridgeError::TaprootBuilderError
    }
}

impl From<TaprootBuilder> for BridgeError {
    fn from(_error: TaprootBuilder) -> Self {
        BridgeError::TaprootBuilderError
    }
}

impl From<bitcoincore_rpc::Error> for BridgeError {
    fn from(err: bitcoincore_rpc::Error) -> Self {
        BridgeError::BitcoinRpcError(err)
    }
}

impl From<MerkleBlockError> for BridgeError {
    fn from(err: MerkleBlockError) -> Self {
        BridgeError::MerkleBlockError(err)
    }
}

impl From<jsonrpsee::core::Error> for BridgeError {
    fn from(err: jsonrpsee::core::Error) -> Self {
        BridgeError::JsonRpcError(err)
    }
}
