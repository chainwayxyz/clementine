use bitcoin::{OutPoint, Txid};
use clementine_circuits::{HashType, PreimageType};

pub mod actor;
pub mod constants;
pub mod db;
pub mod env_writer;
pub mod errors;
pub mod extended_rpc;
pub mod keys;
pub mod merkle;
pub mod mock_env;
pub mod operator;
pub mod script_builder;
pub mod traits;
pub mod transaction_builder;
pub mod user;
pub mod utils;
pub mod verifier;
pub mod config;

pub type ConnectorUTXOTree = Vec<Vec<OutPoint>>;
pub type HashTree = Vec<Vec<HashType>>;
pub type PreimageTree = Vec<Vec<PreimageType>>;
pub type InscriptionTxs = (OutPoint, Txid);

/// Type alias for EVM address
pub type EVMAddress = [u8; 20];

/// Type alias for withdrawal payment, HashType is taproot script hash
pub type WithdrawalPayment = (Txid, HashType);
