//! # Errors
//!
//! This module defines errors, returned by the library.

use bitcoin::{consensus::encode::FromHexError, merkle_tree::MerkleBlockError, BlockHash, Txid};
use core::fmt::Debug;
use jsonrpsee::types::ErrorObject;
use musig2::secp::errors::InvalidScalarBytes;
use std::path::PathBuf;
use thiserror::Error;

/// Errors returned by the bridge.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BridgeError {
    /// Returned when the secp256k1 crate returns an error
    #[error("Secpk256Error: {0}")]
    Secp256k1Error(#[from] secp256k1::Error),
    /// Returned when the bitcoin crate returns an error in the sighash taproot module
    #[error("BitcoinSighashTaprootError: {0}")]
    BitcoinSighashTaprootError(#[from] bitcoin::sighash::TaprootError),
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
    BitcoinRpcError(#[from] bitcoincore_rpc::Error),
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
    BitcoinConsensusEncodeError(#[from] bitcoin::consensus::encode::Error),
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
    MerkleBlockError(#[from] MerkleBlockError),
    /// Merkle Proof Error
    #[error("MerkleProofError")]
    MerkleProofError,
    /// JSON RPC call failed
    #[error("JsonRpcError: {0}")]
    JsonRpcError(#[from] jsonrpsee::core::client::Error),
    /// RPC interface requires a parameter
    #[error("RPC function field {0} is required!")]
    RPCRequiredFieldError(&'static str),
    /// ConfigError is returned when the configuration is invalid
    #[error("ConfigError: {0}")]
    ConfigError(String),
    /// Bitcoin Address Parse Error, probably given address network is invalid
    #[error("BitcoinAddressParseError: {0}")]
    BitcoinAddressParseError(#[from] bitcoin::address::ParseError),
    /// Port error for tests
    #[error("PortError: {0}")]
    PortError(String),
    /// Database error
    #[error("DatabaseError: {0}")]
    DatabaseError(#[from] sqlx::Error),
    /// Database error
    #[error("PgDatabaseError: {0}")]
    PgDatabaseError(String),
    /// Operator tries to claim with different bridge funds with the same withdrawal idx
    #[error("AlreadySpentWithdrawal")]
    AlreadySpentWithdrawal,
    /// There was an error while creating a server.
    #[error("RPC server can't be created: {0}")]
    ServerError(std::io::Error),
    /// When the operators funding utxo is not found
    #[error("OperatorFundingUtxoNotFound: Funding utxo not found, pls send some amount here: {0}, then call the set_operator_funding_utxo RPC")]
    OperatorFundingUtxoNotFound(bitcoin::Address),
    /// OperatorFundingUtxoAmountNotEnough is returned when the operator funding utxo amount is not enough
    #[error("OperatorFundingUtxoAmountNotEnough: Operator funding utxo amount is not enough, pls send some amount here: {0}, then call the set_operator_funding_utxo RPC")]
    OperatorFundingUtxoAmountNotEnough(bitcoin::Address),
    /// OperatorWithdrawalFeeNotSet is returned when the operator withdrawal fee is not set
    #[error("OperatorWithdrawalFeeNotSet")]
    OperatorWithdrawalFeeNotSet,
    /// InvalidKickoffUtxo is returned when the kickoff utxo is invalid
    #[error("InvalidKickoffUtxo")]
    InvalidKickoffUtxo,

    #[error("KeyAggContextError: {0}")]
    KeyAggContextError(#[from] musig2::errors::KeyAggError),

    #[error("KeyAggContextTweakError: {0}")]
    KeyAggContextTweakError(#[from] musig2::errors::TweakError),

    #[error("InvalidScalarBytes: {0}")]
    InvalidScalarBytes(#[from] InvalidScalarBytes),

    #[error("NoncesNotFound")]
    NoncesNotFound,

    #[error("MuSig2VerifyError: {0}")]
    MuSig2VerifyError(#[from] musig2::errors::VerifyError),

    #[error("KickoffOutpointsNotFound")]
    KickoffOutpointsNotFound,
    #[error("DepositInfoNotFound")]
    DepositInfoNotFound,

    #[error("FromHexError: {0}")]
    FromHexError(#[from] FromHexError),

    #[error("FromSliceError: {0}")]
    FromSliceError(#[from] bitcoin::hashes::FromSliceError),

    #[error("InvalidInputUTXO: {0}, {1}")]
    InvalidInputUTXO(Txid, Txid),

    #[error("InvalidOperatorIndex: {0}, {1}")]
    InvalidOperatorIndex(usize, usize),

    #[error("InvalidDepositOutpointGiven: {0}, {1}")]
    InvalidDepositOutpointGiven(usize, usize),

    #[error("NotEnoughFeeForOperator")]
    NotEnoughFeeForOperator,

    #[error("KickoffGeneratorTxNotFound")]
    KickoffGeneratorTxNotFound,

    #[error("KickoffGeneratorTxsTooManyIterations")]
    KickoffGeneratorTxsTooManyIterations,

    #[error("OperatorSlashOrTakeSigNotFound")]
    OperatorSlashOrTakeSigNotFound,

    #[error("OperatorTakesSigNotFound")]
    OperatorTakesSigNotFound,

    #[error("Musig2 error: {0}")]
    Musig2Error(#[from] musig2::secp256k1::Error),

    #[error("Prover returned an error: {0}")]
    ProverError(String),
    #[error("Blockgazer can't synchronize database with active blockchain; Too deep {0}")]
    BlockgazerTooDeep(u64),
    #[error("Fork has happened and it's not recoverable by blockgazer.")]
    BlockgazerFork,
    #[error("Error while de/serializing object: {0}")]
    ProverDeSerializationError(std::io::Error),
    #[error("No header chain proofs for hash {0}")]
    NoHeaderChainProof(BlockHash),
    #[error("Can't read proof assumption receipt from file {0}: {1}")]
    WrongProofAssumption(PathBuf, std::io::Error),

    #[error("ERROR: {0}")]
    Error(String),

    #[error("RPC endpoint returned an error: {0}")]
    TonicError(#[from] tonic::Status),
    #[error("RPC client couldn't start: {0}")]
    RPCClientCouldntStart(#[from] tonic::transport::Error),

    #[error("No root Winternitz secret key is provided in configuration file")]
    NoWinternitzSecretKey,

    #[error("Can't encode/decode data using borsch: {0}")]
    BorschError(std::io::Error),

    #[error("No scripts in TxHandler for the TxIn with index {0}")]
    NoScriptsForTxIn(usize),
    #[error("No script in TxHandler for the index {0}")]
    NoScriptAtIndex(usize),
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
