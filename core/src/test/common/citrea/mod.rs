//! # Citrea Related Utilities
//! # Parameter Builder For Citrea Requests

use crate::errors::BridgeError;
use alloy::primitives::{Bytes, FixedBytes, Uint};
use alloy::sol;
use alloy::sol_types::SolValue;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::Hash;
use bitcoin::{Block, Transaction, Txid};
use bitcoin_merke::BitcoinMerkleTree;

mod bitcoin_merke;
mod e2e;
mod parameters;
mod requests;

pub use e2e::*;
pub use requests::*;
