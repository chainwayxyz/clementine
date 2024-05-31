//! # Bitcoin RPC Trait Interface
//!
//! This module provides trait interface for Bitcoin RPC. This trait can be used
//! to select between real and mock interface.

use crate::errors::BridgeError;
use bitcoin::{OutPoint, ScriptBuf};

pub trait BitcoinRPC {
    fn is_utxo_spent(&self, outpoint: &OutPoint) -> Result<bool, BridgeError>;
    fn check_utxo_address_and_amount(
        &self,
        outpoint: &OutPoint,
        address: &ScriptBuf,
        amount_sats: u64,
    ) -> Result<bool, BridgeError>;
}
