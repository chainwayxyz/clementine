//! # Clementine Core
//!
//! Clementine Core is the backbone of Clementine. As the name suggests,
//! Clementine Core provides core functionalities for Clementine to operate.

#![allow(clippy::too_many_arguments)]

use bitcoin::{OutPoint, Txid};
use serde::{Deserialize, Serialize};

pub mod actor;
pub mod aggregator;
pub mod builder;
pub mod cli;
pub mod config;
pub mod constants;
pub mod database;
pub mod env_writer;
pub mod errors;
pub mod extended_rpc;
pub mod hashes;
pub mod header_chain_prover;
pub mod merkle;
pub mod musig2;
pub mod operator;
pub mod rpc;
pub mod servers;
pub mod traits;
pub mod user;
pub mod utils;
pub mod verifier;
pub mod watchtower;

#[cfg(test)]
mod test_utils;

pub type ConnectorUTXOTree = Vec<Vec<OutPoint>>;
// pub type HashTree = Vec<Vec<HashType>>;
// pub type PreimageTree = Vec<Vec<PreimageType>>;
pub type InscriptionTxs = (OutPoint, Txid);

/// Type alias for EVM address
#[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EVMAddress(#[serde(with = "hex::serde")] pub [u8; 20]);

impl TryFrom<Vec<u8>> for EVMAddress {
    type Error = &'static str;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() == 20 {
            let mut arr = [0u8; 20];
            arr.copy_from_slice(&value);
            Ok(EVMAddress(arr))
        } else {
            Err("Expected a Vec<u8> of length 20")
        }
    }
}
/// Type alias for withdrawal payment, HashType is taproot script hash
// pub type WithdrawalPayment = (Txid, HashType);

#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UTXO {
    pub outpoint: OutPoint,
    pub txout: bitcoin::TxOut,
}

#[derive(Clone, Debug, Copy, Serialize, Deserialize, PartialEq, sqlx::Type)]
#[sqlx(type_name = "bytea")]
pub struct ByteArray66(#[serde(with = "hex::serde")] pub [u8; 66]);

#[derive(Clone, Debug, Copy, Serialize, Deserialize, PartialEq, sqlx::Type)]
#[sqlx(type_name = "bytea")]
pub struct ByteArray32(#[serde(with = "hex::serde")] pub [u8; 32]);

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, sqlx::Type)]
#[sqlx(type_name = "bytea")]
pub struct ByteArray64(#[serde(with = "hex::serde")] pub [u8; 64]);
