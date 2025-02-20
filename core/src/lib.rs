//! # Clementine Core
//!
//! Clementine Core is the backbone of Clementine. As the name suggests,
//! Clementine Core provides core functionalities for Clementine to operate.

#![allow(clippy::too_many_arguments)]

use bitcoin::{OutPoint, Txid};
use serde::{Deserialize, Serialize};

pub mod actor;
pub mod aggregator;
pub mod bitcoin_syncer;
pub mod builder;
pub mod cli;
pub mod config;
pub mod constants;
pub mod database;
pub mod errors;
pub mod extended_rpc;
pub mod header_chain_prover;
pub mod musig2;
pub mod operator;
pub mod rpc;
pub mod servers;
pub mod tx_sender;
pub mod utils;
pub mod verifier;
pub mod watchtower;

#[cfg(test)]
pub mod test;

macro_rules! impl_try_from_vec_u8 {
    ($name:ident, $size:expr) => {
        impl TryFrom<Vec<u8>> for $name {
            type Error = &'static str;

            fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
                if value.len() == $size {
                    Ok($name(value.try_into().unwrap()))
                } else {
                    Err(concat!("Expected a Vec<u8> of length ", stringify!($size)))
                }
            }
        }
    };
}

pub type ConnectorUTXOTree = Vec<Vec<OutPoint>>;
// pub type HashTree = Vec<Vec<HashType>>;
// pub type PreimageTree = Vec<Vec<PreimageType>>;
pub type InscriptionTxs = (OutPoint, Txid);

/// Type alias for EVM address
#[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EVMAddress(#[serde(with = "hex::serde")] pub [u8; 20]);

impl_try_from_vec_u8!(EVMAddress, 20);
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

impl_try_from_vec_u8!(ByteArray66, 66);

#[derive(Clone, Debug, Copy, Serialize, Deserialize, PartialEq, sqlx::Type)]
#[sqlx(type_name = "bytea")]
pub struct ByteArray32(#[serde(with = "hex::serde")] pub [u8; 32]);

impl_try_from_vec_u8!(ByteArray32, 32);

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, sqlx::Type)]
#[sqlx(type_name = "bytea")]
pub struct ByteArray64(#[serde(with = "hex::serde")] pub [u8; 64]);

impl_try_from_vec_u8!(ByteArray64, 64);
