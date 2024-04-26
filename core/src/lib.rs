use bitcoin::{OutPoint, Txid};
use clementine_circuits::{HashType, PreimageType};
use serde::{Deserialize, Serialize};

pub mod actor;
pub mod config;
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

pub type ConnectorUTXOTree = Vec<Vec<OutPoint>>;
pub type HashTree = Vec<Vec<HashType>>;
pub type PreimageTree = Vec<Vec<PreimageType>>;
pub type InscriptionTxs = (OutPoint, Txid);

/// Type alias for EVM address
// pub type EVMAddress = [u8; 20];
#[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct EVMAddress(pub [u8; 20]);
// impl serialize and deserailze for hex string without 0x, use hex:: for EVMAddress
impl Serialize for EVMAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&hex::encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for EVMAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&bytes);
        Ok(EVMAddress(addr))
    }
}

/// Type alias for withdrawal payment, HashType is taproot script hash
pub type WithdrawalPayment = (Txid, HashType);
