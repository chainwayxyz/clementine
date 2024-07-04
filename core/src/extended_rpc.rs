//! # Extended Remote Procedure Call
//!
//! This module provides helpful functions for Bitcoin RPC.

use crate::errors::BridgeError;
use crate::transaction_builder::TransactionBuilder;
use crate::EVMAddress;
use bitcoin::address::NetworkUnchecked;
use bitcoin::Address;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::Transaction;
use bitcoin::TxOut;
use bitcoin::Work;
use bitcoin_mock_rpc::RpcApiWrapper;
use bitcoincore_rpc::json::AddressType;
use bitcoincore_rpc::Auth;
use clementine_circuits::constants::BRIDGE_AMOUNT_SATS;
use crypto_bigint::Encoding;
use crypto_bigint::U256;

#[derive(Debug)]
pub struct ExtendedRpc<R> {
    url: String,
    auth: Auth,
    pub client: R,
}

impl<R> ExtendedRpc<R>
where
    R: RpcApiWrapper,
{
    /// Connects to Bitcoin RPC and returns a new `ExtendedRpc`.
    ///
    /// # Panics
    ///
    /// Panics if it cannot connect to Bitcoin RPC.
    pub fn new(url: String, user: String, password: String) -> Self {
        let auth = Auth::UserPass(user, password);

        let rpc = R::new(&url, auth.clone())
            .unwrap_or_else(|e| panic!("Failed to connect to Bitcoin RPC: {}", e));

        Self {
            url,
            auth,
            client: rpc,
        }
    }

    pub fn confirmation_blocks(&self, txid: &bitcoin::Txid) -> Result<u32, BridgeError> {
        let raw_transaction_results = self.client.get_raw_transaction_info(txid, None)?;

        raw_transaction_results
            .confirmations
            .ok_or(BridgeError::NoConfirmationData)
    }

    pub fn check_utxo_address_and_amount(
        &self,
        outpoint: &OutPoint,
        address: &ScriptBuf,
        amount_sats: u64,
    ) -> Result<bool, BridgeError> {
        let tx = self.client.get_raw_transaction(&outpoint.txid, None)?;

        let current_output = tx.output[outpoint.vout as usize].clone();

        let expected_output = TxOut {
            script_pubkey: address.clone(),
            value: Amount::from_sat(amount_sats),
        };

        Ok(expected_output == current_output)
    }

    pub fn is_utxo_spent(&self, outpoint: &OutPoint) -> Result<bool, BridgeError> {
        let res = self
            .client
            .get_tx_out(&outpoint.txid, outpoint.vout, Some(true))?;

        Ok(res.is_none())
    }

    pub fn generate_dummy_block(&self) -> Result<Vec<bitcoin::BlockHash>, BridgeError> {
        let address = self.client.get_new_address(None, None)?.assume_checked();

        for _ in 0..10 {
            let new_address = self.client.get_new_address(None, None)?.assume_checked();
            let amount = bitcoin::Amount::from_sat(1000); // TODO: Specify the amount to send
            self.client.send_to_address(
                &new_address,
                amount,
                None,
                None,
                None,
                None,
                None,
                None,
            )?;
        }

        Ok(self.client.generate_to_address(1, &address)?)
    }

    pub fn mine_blocks(&self, block_num: u64) -> Result<(), BridgeError> {
        let new_address = self.client.get_new_address(None, None)?.assume_checked();

        self.client.generate_to_address(block_num, &new_address)?;

        Ok(())
    }

    pub fn send_to_address(
        &self,
        address: &Address,
        amount_sats: u64,
    ) -> Result<OutPoint, BridgeError> {
        let txid = self.client.send_to_address(
            address,
            Amount::from_sat(amount_sats),
            None,
            None,
            None,
            None,
            None,
            None,
        )?;

        let tx_result = self.client.get_transaction(&txid, None)?;
        let vout = tx_result.details[0].vout;

        Ok(OutPoint { txid, vout })
    }

    pub fn get_work_at_block(&self, blockheight: u64) -> Result<Work, BridgeError> {
        let block_hash = self.get_block_hash(blockheight)?;
        let block = self.client.get_block(&block_hash)?;
        let work = block.header.work();

        Ok(work)
    }

    pub fn get_block_hash(
        &self,
        blockheight: u64,
    ) -> Result<bitcoin::BlockHash, bitcoincore_rpc::Error> {
        let block_hash = self.client.get_block_hash(blockheight)?;

        Ok(block_hash)
    }

    pub fn get_block_header(
        &self,
        block_hash: &bitcoin::BlockHash,
    ) -> Result<bitcoin::block::Header, bitcoincore_rpc::Error> {
        let block_header = self.client.get_block_header(block_hash)?;

        Ok(block_header)
    }

    pub fn calculate_total_work_between_blocks(
        &self,
        start: u64,
        end: u64,
    ) -> Result<U256, BridgeError> {
        if start == end {
            return Ok(U256::from_be_bytes([0u8; 32]));
        }

        let mut total_work = Work::from_be_bytes([0u8; 32]);
        for i in start + 1..end + 1 {
            total_work = total_work + self.get_work_at_block(i)?;
        }

        let work_bytes = total_work.to_be_bytes();

        Ok(U256::from_be_bytes(work_bytes))
    }

    pub fn get_total_work_as_u256(&self) -> Result<U256, BridgeError> {
        let chain_info = self.client.get_blockchain_info()?;
        let total_work_bytes = chain_info.chain_work;
        let total_work: U256 = U256::from_be_bytes(total_work_bytes.try_into()?);

        Ok(total_work)
    }

    pub fn get_total_work(&self) -> Result<Work, BridgeError> {
        let chain_info = self.client.get_blockchain_info()?;
        let total_work_bytes = chain_info.chain_work;
        let total_work: Work = Work::from_be_bytes(total_work_bytes.try_into()?);

        Ok(total_work)
    }

    pub fn get_block_height(&self) -> Result<u64, BridgeError> {
        let chain_info = self.client.get_blockchain_info()?;
        let block_height = chain_info.blocks;

        Ok(block_height)
    }

    pub fn fundrawtransaction(
        &self,
        tx: &Transaction,
        options: Option<&bitcoincore_rpc::json::FundRawTransactionOptions>,
        is_witness: Option<bool>,
    ) -> Result<bitcoincore_rpc::json::FundRawTransactionResult, bitcoincore_rpc::Error> {
        self.client.fund_raw_transaction(tx, options, is_witness)
    }

    // Following methods are just wrappers around the bitcoincore_rpc::Client methods
    pub fn get_blockchain_info(
        &self,
    ) -> Result<bitcoincore_rpc::json::GetBlockchainInfoResult, bitcoincore_rpc::Error> {
        self.client.get_blockchain_info()
    }

    pub fn get_block_count(&self) -> Result<u64, bitcoincore_rpc::Error> {
        self.client.get_block_count()
    }

    pub fn get_best_block_hash(&self) -> Result<bitcoin::BlockHash, bitcoincore_rpc::Error> {
        self.client.get_best_block_hash()
    }

    pub fn get_raw_transaction(
        &self,
        txid: &bitcoin::Txid,
        block_hash: Option<&bitcoin::BlockHash>,
    ) -> Result<bitcoin::Transaction, bitcoincore_rpc::Error> {
        self.client.get_raw_transaction(txid, block_hash)
    }

    pub fn get_transaction(
        &self,
        txid: &bitcoin::Txid,
        include_watchonly: Option<bool>,
    ) -> Result<bitcoincore_rpc::json::GetTransactionResult, bitcoincore_rpc::Error> {
        self.client.get_transaction(txid, include_watchonly)
    }

    pub fn send_raw_transaction(
        &self,
        tx: &Transaction,
    ) -> Result<bitcoin::Txid, bitcoincore_rpc::Error> {
        self.client.send_raw_transaction(tx)
    }

    pub fn get_block(
        &self,
        block_hash: &bitcoin::BlockHash,
    ) -> Result<bitcoin::Block, bitcoincore_rpc::Error> {
        self.client.get_block(block_hash)
    }
    pub fn get_raw_transaction_info(
        &self,
        txid: &bitcoin::Txid,
        block_hash: Option<&bitcoin::BlockHash>,
    ) -> Result<bitcoincore_rpc::json::GetRawTransactionResult, bitcoincore_rpc::Error> {
        self.client.get_raw_transaction_info(txid, block_hash)
    }

    pub fn check_deposit_utxo(
        &self,
        tx_builder: &TransactionBuilder,
        outpoint: &OutPoint,
        recovery_taproot_address: &Address<NetworkUnchecked>,
        evm_address: &EVMAddress,
        amount_sats: u64,
        confirmation_block_count: u32,
    ) -> Result<(), BridgeError> {
        if self.confirmation_blocks(&outpoint.txid)? < confirmation_block_count {
            return Err(BridgeError::DepositNotFinalized);
        }

        let (deposit_address, _) = tx_builder.generate_deposit_address(
            recovery_taproot_address,
            evm_address,
            BRIDGE_AMOUNT_SATS,
        )?;

        if !self.check_utxo_address_and_amount(
            outpoint,
            &deposit_address.script_pubkey(),
            amount_sats,
        )? {
            return Err(BridgeError::InvalidDepositUTXO);
        }

        if self.is_utxo_spent(outpoint)? {
            return Err(BridgeError::UTXOSpent);
        }

        Ok(())
    }

    /// Generates bitcoins to specified address.
    pub fn generate_to_address(
        &self,
        block_num: u64,
        address: &Address,
    ) -> Result<(), BridgeError> {
        self.client.generate_to_address(block_num, address)?;

        Ok(())
    }

    /// Requests a new Bitcoin address via an RPC call.
    pub fn get_new_address(&self) -> Result<Address, BridgeError> {
        let address = self
            .client
            .get_new_address(None, Some(AddressType::Bech32m));

        Ok(address?.assume_checked())
    }
}

impl<R> Clone for ExtendedRpc<R>
where
    R: RpcApiWrapper,
{
    fn clone(&self) -> Self {
        let new_client = R::new(&self.url, self.auth.clone())
            .unwrap_or_else(|e| panic!("Failed to clone Bitcoin RPC client: {}", e));

        Self {
            url: self.url.clone(),
            auth: self.auth.clone(),
            client: new_client,
        }
    }
}

impl<R> Default for ExtendedRpc<R>
where
    R: RpcApiWrapper,
{
    fn default() -> Self {
        Self::new(
            "http://localhost:18443".to_string(),
            "admin".to_string(),
            "admin".to_string(),
        )
    }
}
