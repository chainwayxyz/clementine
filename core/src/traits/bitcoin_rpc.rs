//! # Bitcoin RPC Trait Interface
//!
//! This module provides trait interface for Bitcoin RPC. This trait can be used
//! to select between real and mock interface.

use crate::errors::BridgeError;
use bitcoin::{OutPoint, ScriptBuf, Transaction};

pub trait BitcoinRPC {
    /// Should check if an UTXO is spent or not.
    fn is_utxo_spent(&self, outpoint: &OutPoint) -> Result<bool, BridgeError>;

    /// Should check if output checked from `outpoint` equals to new output
    /// created from `address` and `amount_sats`.
    fn check_utxo_address_and_amount(
        &self,
        outpoint: &OutPoint,
        address: &ScriptBuf,
        amount_sats: u64,
    ) -> Result<bool, BridgeError>;

    /// Should send raw transaction to Bitcoin.
    fn send_raw_transaction(
        &self,
        tx: &Transaction,
    ) -> Result<bitcoin::Txid, bitcoincore_rpc::Error>;
}
