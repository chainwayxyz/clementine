//! # Errors
//!
//! This module defines errors, returned by the library.

use crate::{builder::transaction::TransactionType};
use bitcoin::{consensus::encode::FromHexError, BlockHash, FeeRate, OutPoint, Txid};
use core::fmt::Debug;
use jsonrpsee::types::ErrorObject;
use secp256k1::musig;
use std::path::PathBuf;
use thiserror::Error;

/// Errors returned by the bridge.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BridgeError {
    /// Returned if there is no confirmation data
    #[error("NoConfirmationData")]
    NoConfirmationData,
    /// For Vec<u8> conversion
    #[error("VecConversionError")]
    VecConversionError,
    /// For TryFromSliceError
    #[error("TryFromSliceError")]
    TryFromSliceError,
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
    /// Merkle Proof Error
    #[error("MerkleProofError")]
    MerkleProofError,

    #[error("RPC function field {0} is required!")]
    RPCRequiredParam(&'static str),
    #[error("RPC function parameter {0} is malformed: {1}")]
    RPCParamMalformed(String, String),
    #[error("RPC stream ended unexpectedly: {0}")]
    RPCStreamEndedUnexpectedly(String),
    #[error("Invalid response from an RPC endpoint: {0}")]
    RPCInvalidResponse(String),
    #[error("RPCBroadcastSendError: {0}")]
    RPCBroadcastSendError(String),
    /// ConfigError is returned when the configuration is invalid
    #[error("ConfigError: {0}")]
    ConfigError(String),
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
    #[error("Operator idx {0} was not found in the DB")]
    OperatorNotFound(u32),
    #[error("Transaction {0:?} is not confirmed, cannot retrieve blockhash")]
    TransactionNotConfirmed(Txid),

    #[error("Error while generating musig nonces: {0}")]
    MusigNonceGenFailed(#[from] musig::MusigNonceGenError),
    #[error("Error while signing a musig member: {0}")]
    MusigSignFailed(#[from] musig::MusigSignError),
    #[error("Error while tweaking a musig member: {0}")]
    MusigTweakFailed(#[from] musig::MusigTweakErr),
    #[error("Error while parsing a musig member: {0}")]
    MusigParseError(#[from] musig::ParseError),

    #[error("Insufficient Context data for the requested TxHandler")]
    InsufficientContext,

    #[error("NoncesNotFound")]
    NoncesNotFound,

    #[error("State machine received event that it doesn't know how to handle: {0}")]
    UnhandledEvent(String),

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

    #[error("ConversionError: {0}")]
    ConversionError(String),

    #[error("ERROR: {0}")]
    Error(String),

    #[error("No root Winternitz secret key is provided in configuration file")]
    NoWinternitzSecretKey,

    #[error("Can't encode/decode data using borsh: {0}")]
    BorshError(std::io::Error),

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
    #[error("NofN sighash count does not match. Expected: {0} Found: {1}")]
    NofNSighashMismatch(usize, usize),
    #[error("Operator sighash count does not match. Expected: {0} Found: {1}")]
    OperatorSighashMismatch(usize, usize),

    #[error(
        "The length of watchtower challenge commit data does not match expected number of bytes"
    )]
    InvalidWatchtowerChallengeData,
    #[error("The length of full assert commit data does not match the number of steps")]
    InvalidCommitData,
    #[error(
        "The size of commit data of step {0} does not match the needed size. Expected {1}, got {2}"
    )]
    InvalidStepCommitData(usize, usize, usize),

    #[error("BitvmSetupNotFound for operator {0}, deposit_txid {1}")]
    BitvmSetupNotFound(i32, Txid),

    #[error("WatchtowerPublicHashesNotFound for operator {0}, deposit_txid {1}")]
    WatchtowerPublicHashesNotFound(i32, Txid),

    #[error("Challenge addresses of the watchtower {0} for the operator {1} not found")]
    WatchtowerChallengeAddressesNotFound(u32, u32),

    #[error("MissingWitnessData")]
    MissingWitnessData,
    #[error("MissingSpendInfo")]
    MissingSpendInfo,

    #[error("InvalidAssertTxAddrs")]
    InvalidAssertTxAddrs,
    #[error("Not enough assert tx scripts given")]
    InvalidAssertTxScripts,
    #[error("Invalid response from Citrea: {0}")]
    InvalidCitreaResponse(String),

    #[error("Not enough operators")]
    NotEnoughOperators,

    #[error("Bitcoin RPC signing error: {0:?}")]
    BitcoinRPCSigningError(Vec<String>),

    #[error("Can't estimate fees: {0:?}")]
    FeeEstimationError(Vec<String>),

    #[error("Fee payer transaction not found")]
    FeePayerTxNotFound,

    #[error("No confirmed fee payer transaction found")]
    ConfirmedFeePayerTxNotFound,

    #[error("P2A anchor output not found in transaction")]
    P2AAnchorNotFound,

    #[error("Arithmetic overflow")]
    Overflow,

    #[error("Effective fee rate is lower than required")]
    EffectiveFeeRateLowerThanRequired,

    #[error("Can't bump fee for Txid of {0} and feerate of {1}: {2}")]
    BumpFeeError(Txid, FeeRate, String),

    #[error("Cannot bump fee - UTXO is already spent")]
    BumpFeeUTXOSpent(OutPoint),

    #[error("Encountered multiple winternitz scripts when attempting to commit to only one.")]
    MultipleWinternitzScripts,
    #[error("Encountered multiple preimage reveal scripts when attempting to commit to only one.")]
    MultiplePreimageRevealScripts,

    #[error("Sighash stream ended prematurely")]
    SighashStreamEndedPrematurely,

    #[error("{0} input channel for {1} ended prematurely")]
    ChannelEndedPrematurely(&'static str, &'static str),

    // TODO: Couldn't put `from[SendError<T>]` because of generics, find a way
    /// 0: Data name, 1: Error message
    #[error("Error while sending {0} data: {1}")]
    SendError(&'static str, String),

    #[error("Eyre error: {0}")]
    Eyre(#[from] eyre::Report),

    #[error("Transaction is already in block: {0}")]
    TransactionAlreadyInBlock(BlockHash),

    #[error("User's withdrawal UTXO not set for withdrawal index: {0}")]
    UsersWithdrawalUtxoNotSetForWithdrawalIndex(u32),
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

