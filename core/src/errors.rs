//! # Errors
//!
//! This module defines errors, returned by the library.

use bitcoin::{consensus::encode::FromHexError, merkle_tree::MerkleBlockError, BlockHash, Txid};
use core::fmt::Debug;
use jsonrpsee::types::ErrorObject;
use secp256k1::musig;
use std::path::PathBuf;
use thiserror::Error;

/// Errors returned by the bridge.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BridgeError {
    /// Returned when the bitcoin::secp256k1 crate returns an error
    #[error("Secpk256Error: {0}")]
    BitcoinSecp256k1Error(#[from] bitcoin::secp256k1::Error),
    /// Returned when the bitcoin crate returns an error in the sighash taproot module
    #[error("BitcoinSighashTaprootError: {0}")]
    BitcoinSighashTaprootError(#[from] bitcoin::sighash::TaprootError),
    #[error("Invalid bitcoin block hash: {0}")]
    BitcoinBlockHashInvalid(#[from] bitcoin::hex::HexToArrayError),

    #[error("Secp256k1 returned an error: {0}")]
    Secp256k1Error(#[from] secp256k1::Error),
    #[error("Scalar can't be build: {0}")]
    Secp256k1ScalarOutOfRange(#[from] secp256k1::scalar::OutOfRangeError),

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
    #[error("TxOutputNotFound")]
    TxOutputNotFound,
    #[error("WitnessAlreadySet")]
    WitnessAlreadySet,
    #[error("Script with index {0} not found for transaction")]
    ScriptNotFound(usize),
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

    #[error("JsonRpcError: {0}")]
    JsonRpcError(#[from] jsonrpsee::core::client::Error),
    #[error("RPC function field {0} is required!")]
    RPCRequiredParam(&'static str),
    #[error("RPC function parameter {0} is malformed: {1}")]
    RPCParamMalformed(String, String),
    #[error("RPC stream ended unexpectedly: {0}")]
    RPCStreamEndedUnexpectedly(String),
    #[error("Invalid response from an RPC endpoint: {0}")]
    RPCInvalidResponse(String),
    #[error("RPCBroadcastRecvError: {0}")]
    RPCBroadcastRecvError(#[from] tokio::sync::broadcast::error::RecvError),
    #[error("RPCBroadcastSendError: {0}")]
    RPCBroadcastSendError(String),
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
    /// Invalid binding address given in config file
    #[error("Invalid server address: {0}")]
    InvalidServerAddress(#[from] core::net::AddrParseError),
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

    #[error("Error while generating musig nonces: {0}")]
    MusigNonceGenFailed(#[from] musig::MusigNonceGenError),
    #[error("Error while signing a musig member: {0}")]
    MusigSignFailed(#[from] musig::MusigSignError),
    #[error("Error while tweaking a musig member: {0}")]
    MusigTweakFailed(#[from] musig::MusigTweakErr),
    #[error("Error while parsing a musig member: {0}")]
    MusigParseError(#[from] musig::ParseError),

    #[error("NoncesNotFound")]
    NoncesNotFound,

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

    #[error("Can't encode/decode data using borsh: {0}")]
    BorshError(std::io::Error),

    #[error("No scripts in TxHandler for the TxIn with index {0}")]
    NoScriptsForTxIn(usize),
    #[error("No script in TxHandler for the index {0}")]
    NoScriptAtIndex(usize),

    #[error("BitvmSetupNotFound for operator {0}, sequential_collateral_tx {1}, kickoff {2}")]
    BitvmSetupNotFound(i32, i32, i32),

    #[error("WatchtowerPublicHashesNotFound for operator {0}, sequential_collateral_tx {1}, kickoff {2}")]
    WatchtowerPublicHashesNotFound(i32, i32, i32),

    #[error("Challenge addresses of the watchtower {0} for the operator {1} not found")]
    WatchtowerChallengeAddressesNotFound(u32, u32),

    #[error("MissingWitnessData")]
    MissingWitnessData,
    #[error("MissingSpendInfo")]
    MissingSpendInfo,

    #[error("InvalidAssertTxAddrs")]
    InvalidAssertTxAddrs,
    #[error("Invalid response from Citrea: {0}")]
    InvalidCitreaResponse(String),

    #[error("Not enough operators")]
    NotEnoughOperators,

    #[error("Bitcoin RPC signing error: {0:?}")]
    BitcoinRPCSigningError(Vec<String>),

    #[error("Fee estimation error: {0:?}")]
    FeeEstimationError(Vec<String>),

    #[error("Fee payer transaction not found")]
    FeePayerTxNotFound,

    #[error("No confirmed fee payer transaction found")]
    ConfirmedFeePayerTxNotFound,

    #[error("P2A anchor output not found in transaction")]
    P2AAnchorNotFound,
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
