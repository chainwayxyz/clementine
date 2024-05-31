//! # Bitcoin Simulator
//!
//! This module is a wrapper for Bitcoin simulators. It tries to simulate what
//! `ExtendedRpc` does.

use crate::errors::BridgeError;
use crate::traits::bitcoin_rpc::BitcoinRPC;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin_simulator::database::Database;
use std::io::Error;

pub struct BitcoinMockRPC {
    database: Database,
}

impl BitcoinMockRPC {
    /// Creates a new Bitcoin simulator database.
    ///
    /// # Panics
    ///
    /// Panics if database connection cannot be established.
    pub fn new() -> Self {
        let database = Database::connect_temporary_database().unwrap();

        Self { database }
    }
}

impl BitcoinRPC for BitcoinMockRPC {
    fn is_utxo_spent(&self, outpoint: &OutPoint) -> Result<bool, BridgeError> {
        match self
            .database
            .check_if_output_is_spent(outpoint.txid.to_string().as_str(), outpoint.vout)
        {
            Ok(r) => Ok(r),
            Err(e) => Err(BridgeError::DatabaseError(sqlx::Error::Io(Error::other(
                e.to_string(),
            )))),
        }
    }

    fn check_utxo_address_and_amount(
        &self,
        outpoint: &OutPoint,
        address: &ScriptBuf,
        amount_sats: u64,
    ) -> Result<bool, BridgeError> {
        todo!()
    }

    fn send_raw_transaction(
        &self,
        tx: &bitcoin::Transaction,
    ) -> Result<bitcoin::Txid, bitcoincore_rpc::Error> {
        let txid = tx.compute_txid();

        match self.database.insert_transaction_unconditionally(tx) {
            Ok(_) => Ok(txid),
            Err(e) => Err(bitcoincore_rpc::Error::ReturnedError(e.to_string())),
        }
    }
}
