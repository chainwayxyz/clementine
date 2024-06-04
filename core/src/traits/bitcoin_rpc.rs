//! # Bitcoin RPC Trait Interface
//!
//! This module provides trait interface for Bitcoin RPC. This trait can be used
//! to select between real and mock interface.

use crate::{errors::BridgeError, transaction_builder::TransactionBuilder, EVMAddress};
use bitcoin::{address::NetworkUnchecked, Address, OutPoint, ScriptBuf, Transaction, Work};
use crypto_bigint::U256;

pub trait BitcoinRPC: std::marker::Send + std::marker::Sync + Clone + 'static {
    /// Should create a new implementation.
    fn new(url: String, user: String, password: String) -> Self;

    fn confirmation_blocks(&self, txid: &bitcoin::Txid) -> Result<u32, BridgeError>;

    /// Should check if output checked from `outpoint` equals to new output
    /// created from `address` and `amount_sats`.
    fn check_utxo_address_and_amount(
        &self,
        outpoint: &OutPoint,
        address: &ScriptBuf,
        amount_sats: u64,
    ) -> Result<bool, BridgeError>;

    /// Should check if an UTXO is spent or not.
    fn is_utxo_spent(&self, outpoint: &OutPoint) -> Result<bool, BridgeError>;

    fn generate_dummy_block(&self) -> Result<Vec<bitcoin::BlockHash>, BridgeError>;

    fn mine_blocks(&self, block_num: u64) -> Result<(), BridgeError>;

    fn send_to_address(&self, address: &Address, amount_sats: u64)
        -> Result<OutPoint, BridgeError>;

    fn get_work_at_block(&self, blockheight: u64) -> Result<Work, BridgeError>;

    fn get_block_header(
        &self,
        block_hash: &bitcoin::BlockHash,
    ) -> Result<bitcoin::block::Header, bitcoincore_rpc::Error>;

    fn get_block_hash(
        &self,
        blockheight: u64,
    ) -> Result<bitcoin::BlockHash, bitcoincore_rpc::Error>;

    fn calculate_total_work_between_blocks(
        &self,
        start: u64,
        end: u64,
    ) -> Result<U256, BridgeError>;

    fn get_total_work_as_u256(&self) -> Result<U256, BridgeError>;

    fn get_total_work(&self) -> Result<Work, BridgeError>;

    fn get_block_height(&self) -> Result<u64, BridgeError>;

    fn fundrawtransaction(
        &self,
        tx: &Transaction,
        options: Option<&bitcoincore_rpc::json::FundRawTransactionOptions>,
        is_witness: Option<bool>,
    ) -> Result<bitcoincore_rpc::json::FundRawTransactionResult, bitcoincore_rpc::Error>;

    fn get_blockchain_info(
        &self,
    ) -> Result<bitcoincore_rpc::json::GetBlockchainInfoResult, bitcoincore_rpc::Error>;

    fn get_block_count(&self) -> Result<u64, bitcoincore_rpc::Error>;

    fn get_best_block_hash(&self) -> Result<bitcoin::BlockHash, bitcoincore_rpc::Error>;

    fn get_raw_transaction(
        &self,
        txid: &bitcoin::Txid,
        block_hash: Option<&bitcoin::BlockHash>,
    ) -> Result<bitcoin::Transaction, bitcoincore_rpc::Error>;

    fn get_transaction(
        &self,
        txid: &bitcoin::Txid,
        include_watchonly: Option<bool>,
    ) -> Result<bitcoincore_rpc::json::GetTransactionResult, bitcoincore_rpc::Error>;

    /// Should send raw transaction to Bitcoin.
    fn send_raw_transaction(
        &self,
        tx: &Transaction,
    ) -> Result<bitcoin::Txid, bitcoincore_rpc::Error>;

    fn get_block(
        &self,
        block_hash: &bitcoin::BlockHash,
    ) -> Result<bitcoin::Block, bitcoincore_rpc::Error>;

    fn get_raw_transaction_info(
        &self,
        txid: &bitcoin::Txid,
        block_hash: Option<&bitcoin::BlockHash>,
    ) -> Result<bitcoincore_rpc::json::GetRawTransactionResult, bitcoincore_rpc::Error>;

    fn check_deposit_utxo(
        &self,
        tx_builder: &TransactionBuilder,
        outpoint: &OutPoint,
        recovery_taproot_address: &Address<NetworkUnchecked>,
        evm_address: &EVMAddress,
        amount_sats: u64,
        confirmation_block_count: u32,
    ) -> Result<(), BridgeError>;
}
