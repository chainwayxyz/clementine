//! # Clementine Core
//!
//! Clementine Core is the backbone of Clementine. As the name suggests,
//! Clementine Core provides core functionalities for Clementine to operate.

use bitcoin::{OutPoint, Txid};
use clementine_circuits::{HashType, PreimageType};
use serde::{Deserialize, Serialize};

pub mod actor;
pub mod cli;
pub mod config;
pub mod database;
pub mod env_writer;
pub mod errors;
pub mod extended_rpc;
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
pub type HashTree = Vec<Vec<HashType>>;
pub type PreimageTree = Vec<Vec<PreimageType>>;
pub type InscriptionTxs = (OutPoint, Txid);

/// Type alias for EVM address
#[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EVMAddress(#[serde(with = "hex::serde")] pub [u8; 20]);

/// Type alias for withdrawal payment, HashType is taproot script hash
pub type WithdrawalPayment = (Txid, HashType);

#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PsbtOutPoint {
    /// The referenced transaction's txid.
    pub tx: bitcoin::Transaction,
    /// The index of the referenced output in its transaction's vout.
    pub vout: u32,
}

use serde::de::{self, Deserializer, SeqAccess, Visitor};
use serde::ser::{SerializeTuple, Serializer};

#[derive(Clone, Debug)]
pub struct ByteArray66(pub [u8; 66]);

impl Serialize for ByteArray66 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_tuple(self.0.len())?;
        for byte in &self.0 {
            seq.serialize_element(byte)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for ByteArray66 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ByteArray66Visitor;

        impl<'de> Visitor<'de> for ByteArray66Visitor {
            type Value = ByteArray66;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a byte array of length 66")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<ByteArray66, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut array = [0u8; 66];
                for (i, byte) in array.iter_mut().enumerate() {
                    *byte = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(i, &self))?;
                }
                Ok(ByteArray66(array))
            }
        }

        deserializer.deserialize_tuple(66, ByteArray66Visitor)
    }
}
