//! # Errors
//!
//! This module defines errors, returned by the library.

use bitcoin::{
    merkle_tree::MerkleBlockError,
    taproot::{TaprootBuilder, TaprootBuilderError},
};
use core::fmt::Debug;
use jsonrpsee::types::{ErrorObject, ErrorObjectOwned};
use musig2::secp::errors::InvalidScalarBytes;
use std::array::TryFromSliceError;
use thiserror::Error;

/// Errors related to periods.
#[derive(Debug, Error)]
pub enum InvalidPeriodError {
    #[error("DepositPeriodMismatch")]
    WithdrawalPeriodMismatch,
    #[error("DepositPeriodMismatch")]
    PreimageRevealPeriodMismatch,
    #[error("DepositPeriodMismatch")]
    InscriptionPeriodMismatch,
}

/// Errors returned by the bridge.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BridgeError {
    /// Returned when the period is invalid
    #[error("InvalidPeriod")]
    InvalidPeriod(InvalidPeriodError),
    /// Returned when the secp256k1 crate returns an error
    #[error("Secpk256Error: {0}")]
    Secpk256Error(secp256k1::Error),
    /// Returned when the bitcoin crate returns an error in the sighash taproot module
    #[error("BitcoinSighashTaprootError: {0}")]
    BitcoinSighashTaprootError(bitcoin::sighash::TaprootError),
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
    #[error("BitcoinTransactionError: {0}")]
    BitcoinConsensusEncodeError(bitcoin::consensus::encode::Error),
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
    /// JSON RPC call failed
    #[error("JsonRpcError: {0}")]
    JsonRpcError(jsonrpsee::core::client::Error),
    /// Given key pair is invalid and new pairs can't be generated randomly
    #[error("InvalidKeyPair")]
    InvalidKeyPair(std::io::Error),
    /// ConfigError is returned when the configuration is invalid
    #[error("ConfigError: {0}")]
    ConfigError(String),
    /// Bitcoin Address Parse Error, probably given address network is invalid
    #[error("BitcoinAddressParseError: {0}")]
    BitcoinAddressParseError(bitcoin::address::ParseError),
    /// Port error for tests
    #[error("PortError: {0}")]
    PortError(String),
    /// Database error
    #[error("DatabaseError: {0}")]
    DatabaseError(sqlx::Error),
    /// Operator tries to claim with different bridge funds with the same withdrawal idx
    #[error("AlreadySpentWithdrawal")]
    AlreadySpentWithdrawal,
    /// There was an error while creating a server.
    #[error("ServerError")]
    ServerError(std::io::Error),
    /// When the operators funding utxo is not found
    #[error("OperatorFundingUtxoNotFound: Funding utxo not found, pls send some amount here: {0}, then call the set_operator_funding_utxo RPC")]
    OperatorFundingUtxoNotFound(bitcoin::Address),
    /// OperatorFundingUtxoAmountNotEnough is returned when the operator funding utxo amount is not enough
    #[error("OperatorFundingUtxoAmountNotEnough: Operator funding utxo amount is not enough, pls send some amount here: {0}, then call the set_operator_funding_utxo RPC")]
    OperatorFundingUtxoAmountNotEnough(bitcoin::Address),
    /// InvalidKickoffUtxo is returned when the kickoff utxo is invalid
    #[error("InvalidKickoffUtxo")]
    InvalidKickoffUtxo,

    #[error("KeyAggContextError: {0}")]
    KeyAggContextError(musig2::errors::KeyAggError),

    #[error("KeyAggContextTweakError: {0}")]
    KeyAggContextTweakError(musig2::errors::TweakError),

    #[error("InvalidScalarBytes: {0}")]
    InvalidScalarBytes(InvalidScalarBytes),

    #[error("NoncesNotFound")]
    NoncesNotFound,

    #[error("MuSig2VerifyError: {0}")]
    MuSig2VerifyError(musig2::errors::VerifyError),

    #[error("KickoffOutpointsNotFound")]
    KickoffOutpointsNotFound,
    #[error("DepositInfoNotFound")]
    DepositInfoNotFound,
}

impl Into<ErrorObject<'static>> for BridgeError {
    fn into(self) -> ErrorObjectOwned {
        ErrorObject::owned(-30000, format!("{:?}", self), Some(1))
    }
}

impl From<secp256k1::Error> for BridgeError {
    fn from(err: secp256k1::Error) -> Self {
        BridgeError::Secpk256Error(err)
    }
}

impl From<bitcoin::sighash::TaprootError> for BridgeError {
    fn from(err: bitcoin::sighash::TaprootError) -> Self {
        BridgeError::BitcoinSighashTaprootError(err)
    }
}

impl From<Vec<u8>> for BridgeError {
    fn from(_error: Vec<u8>) -> Self {
        BridgeError::VecConversionError
    }
}

impl From<TryFromSliceError> for BridgeError {
    fn from(_error: TryFromSliceError) -> Self {
        BridgeError::TryFromSliceError
    }
}

impl From<bitcoin::consensus::encode::Error> for BridgeError {
    fn from(err: bitcoin::consensus::encode::Error) -> Self {
        BridgeError::BitcoinConsensusEncodeError(err)
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

impl From<jsonrpsee::core::client::Error> for BridgeError {
    fn from(err: jsonrpsee::core::client::Error) -> Self {
        BridgeError::JsonRpcError(err)
    }
}

impl From<bitcoin::address::ParseError> for BridgeError {
    fn from(err: bitcoin::address::ParseError) -> Self {
        BridgeError::BitcoinAddressParseError(err)
    }
}

impl From<sqlx::Error> for BridgeError {
    fn from(err: sqlx::Error) -> Self {
        BridgeError::DatabaseError(err)
    }
}

impl From<musig2::errors::KeyAggError> for BridgeError {
    fn from(err: musig2::errors::KeyAggError) -> Self {
        BridgeError::KeyAggContextError(err)
    }
}

impl From<musig2::errors::TweakError> for BridgeError {
    fn from(err: musig2::errors::TweakError) -> Self {
        BridgeError::KeyAggContextTweakError(err)
    }
}

impl From<InvalidScalarBytes> for BridgeError {
    fn from(err: InvalidScalarBytes) -> Self {
        BridgeError::InvalidScalarBytes(err)
    }
}

impl From<musig2::errors::VerifyError> for BridgeError {
    fn from(err: musig2::errors::VerifyError) -> Self {
        BridgeError::MuSig2VerifyError(err)
    }
}
