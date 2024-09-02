//! # Clementine Core
//!
//! Clementine Core is the backbone of Clementine. As the name suggests,
//! Clementine Core provides core functionalities for Clementine to operate.

#![allow(clippy::too_many_arguments)]

use bitcoin::{OutPoint, Txid};
// use clementine_circuits::{HashType, PreimageType};
use serde::{Deserialize, Serialize};

pub mod actor;
pub mod aggregator;
pub mod cli;
pub mod config;
pub mod constants;
pub mod database;
pub mod env_writer;
pub mod errors;
pub mod extended_rpc;
pub mod hashes;
pub mod merkle;
pub mod mock;
pub mod musig2;
pub mod operator;
pub mod script_builder;
pub mod servers;
pub mod traits;
pub mod transaction_builder;
pub mod user;
pub mod utils;
pub mod verifier;

pub type ConnectorUTXOTree = Vec<Vec<OutPoint>>;
// pub type HashTree = Vec<Vec<HashType>>;
// pub type PreimageTree = Vec<Vec<PreimageType>>;
pub type InscriptionTxs = (OutPoint, Txid);

/// Type alias for EVM address
#[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EVMAddress(#[serde(with = "hex::serde")] pub [u8; 20]);

/// Type alias for withdrawal payment, HashType is taproot script hash
// pub type WithdrawalPayment = (Txid, HashType);

#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UTXO {
    pub outpoint: OutPoint,
    pub txout: bitcoin::TxOut,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, sqlx::Type)]
#[sqlx(type_name = "bytea")]
pub struct ByteArray66(#[serde(with = "hex::serde")] pub [u8; 66]);
