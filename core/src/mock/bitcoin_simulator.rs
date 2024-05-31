//! # Bitcoin Simulator
//!
//! This module is a wrapper for Bitcoin simulators. It tries to simulate what
//! `ExtendedRpc` does.

use crate::errors::BridgeError;
use crate::traits::bitcoin_rpc::BitcoinRPC;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::TxOut;
use bitcoin_simulator::database::Database;
use std::io::Error;

pub struct BitcoinMockRPC {
    database: Database,
}

impl BitcoinRPC for BitcoinMockRPC {
    /// Creates a new Bitcoin simulator database.
    ///
    /// # Panics
    ///
    /// Panics if database connection cannot be established.
    fn new(_url: String, _user: String, _password: String) -> Self {
        let database = Database::connect_temporary_database().unwrap();

        Self { database }
    }

    fn confirmation_blocks(&self, _txid: &bitcoin::Txid) -> Result<u32, BridgeError> {
        todo!()
    }

    fn check_utxo_address_and_amount(
        &self,
        outpoint: &OutPoint,
        address: &ScriptBuf,
        amount_sats: u64,
    ) -> Result<bool, BridgeError> {
        let current_output = match self
            .database
            .get_prev_output(outpoint.txid.to_string().as_str(), outpoint.vout)
        {
            Ok(txout) => txout,
            Err(e) => {
                return Err(BridgeError::BitcoinRpcError(
                    bitcoincore_rpc::Error::ReturnedError(e.to_string()),
                ))
            }
        };

        let expected_output = TxOut {
            script_pubkey: address.clone(),
            value: Amount::from_sat(amount_sats),
        };

        Ok(expected_output == current_output)
    }

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

    fn generate_dummy_block(&self) -> Result<Vec<bitcoin::BlockHash>, BridgeError> {
        todo!()
    }

    fn mine_blocks(&self, _block_num: u64) -> Result<(), BridgeError> {
        todo!()
    }

    fn send_to_address(
        &self,
        _address: &bitcoin::Address,
        _amount_sats: u64,
    ) -> Result<OutPoint, BridgeError> {
        todo!()
    }

    fn get_work_at_block(&self, _blockheight: u64) -> Result<bitcoin::Work, BridgeError> {
        todo!()
    }

    fn get_block_header(
        &self,
        _block_hash: &bitcoin::BlockHash,
    ) -> Result<bitcoin::block::Header, bitcoincore_rpc::Error> {
        todo!()
    }

    fn get_block_hash(
        &self,
        _blockheight: u64,
    ) -> Result<bitcoin::BlockHash, bitcoincore_rpc::Error> {
        todo!()
    }

    fn calculate_total_work_between_blocks(
        &self,
        _start: u64,
        _end: u64,
    ) -> Result<crypto_bigint::U256, BridgeError> {
        todo!()
    }

    fn get_total_work_as_u256(&self) -> Result<crypto_bigint::U256, BridgeError> {
        todo!()
    }

    fn get_total_work(&self) -> Result<bitcoin::Work, BridgeError> {
        todo!()
    }

    fn get_block_height(&self) -> Result<u64, BridgeError> {
        todo!()
    }

    fn fundrawtransaction(
        &self,
        _tx: &bitcoin::Transaction,
        _options: Option<&bitcoincore_rpc::json::FundRawTransactionOptions>,
        _is_witness: Option<bool>,
    ) -> Result<bitcoincore_rpc::json::FundRawTransactionResult, bitcoincore_rpc::Error> {
        todo!()
    }

    fn get_blockchain_info(
        &self,
    ) -> Result<bitcoincore_rpc::json::GetBlockchainInfoResult, bitcoincore_rpc::Error> {
        todo!()
    }

    fn get_block_count(&self) -> Result<u64, bitcoincore_rpc::Error> {
        todo!()
    }

    fn get_best_block_hash(&self) -> Result<bitcoin::BlockHash, bitcoincore_rpc::Error> {
        todo!()
    }

    fn get_raw_transaction(
        &self,
        _txid: &bitcoin::Txid,
        _block_hash: Option<&bitcoin::BlockHash>,
    ) -> Result<bitcoin::Transaction, bitcoincore_rpc::Error> {
        todo!()
    }

    fn get_transaction(
        &self,
        _txid: &bitcoin::Txid,
        _include_watchonly: Option<bool>,
    ) -> Result<bitcoincore_rpc::json::GetTransactionResult, bitcoincore_rpc::Error> {
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

    fn get_block(
        &self,
        _block_hash: &bitcoin::BlockHash,
    ) -> Result<bitcoin::Block, bitcoincore_rpc::Error> {
        todo!()
    }

    fn get_raw_transaction_info(
        &self,
        _txid: &bitcoin::Txid,
        _block_hash: Option<&bitcoin::BlockHash>,
    ) -> Result<bitcoincore_rpc::json::GetRawTransactionResult, bitcoincore_rpc::Error> {
        todo!()
    }

    fn check_deposit_utxo(
        &self,
        _tx_builder: &crate::transaction_builder::TransactionBuilder,
        _outpoint: &OutPoint,
        _recovery_taproot_address: &bitcoin::Address<bitcoin::address::NetworkUnchecked>,
        _evm_address: &crate::EVMAddress,
        _amount_sats: u64,
        _confirmation_block_count: u32,
    ) -> Result<(), BridgeError> {
        todo!()
    }
}
