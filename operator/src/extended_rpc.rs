use bitcoin::Address;
use bitcoin::Amount;
use bitcoin::OutPoint;

use bitcoin::ScriptBuf;
use bitcoin::Transaction;
use bitcoin::TxOut;
use bitcoin::Work;
use bitcoincore_rpc::Auth;
use bitcoincore_rpc::Client;
use bitcoincore_rpc::RpcApi;
use crypto_bigint::Encoding;
use crypto_bigint::U256;

#[derive(Debug)]
pub struct ExtendedRpc {
    pub inner: Client,
}

impl ExtendedRpc {
    pub fn new() -> Self {
        let rpc = Client::new(
            "http://localhost:18443/wallet/admin",
            Auth::UserPass("admin".to_string(), "admin".to_string()),
        )
        .unwrap_or_else(|e| panic!("Failed to connect to Bitcoin RPC: {}", e));
        Self { inner: rpc }
    }

    pub fn confirmation_blocks(&self, txid: &bitcoin::Txid) -> u32 {
        self.inner
            .get_raw_transaction_info(txid, None)
            .unwrap()
            .confirmations
            .unwrap()
    }

    pub fn check_utxo_address_and_amount(
        &self,
        outpoint: &OutPoint,
        address: &ScriptBuf,
        amount_sats: u64,
    ) -> bool {
        let tx = self
            .inner
            .get_raw_transaction(&outpoint.txid, None)
            .unwrap_or_else(|e| panic!("Failed to get transaction: {}", e));
        let current_output = tx.output[outpoint.vout as usize].clone();
        let expected_output = TxOut {
            script_pubkey: address.clone(),
            value: Amount::from_sat(amount_sats),
        };
        return expected_output == current_output;
        // println!("current_output: {:?}", current_output);
        // println!("expected_output: {:?}", expected_output);
        // current_output.value.to_sat() == expected_output.value.to_sat()
        //     && current_output.script_pubkey.as_bytes() == expected_output.script_pubkey.as_bytes()
    }

    pub fn is_utxo_spent(&self, _outpoint: &OutPoint) -> bool {
        let res = self.inner.get_tx_out(&_outpoint.txid, _outpoint.vout, Some(true)).unwrap();
        return res.is_none();
    }

    pub fn generate_dummy_block(&self) -> Vec<bitcoin::BlockHash> {
        // Use `generatetoaddress` or similar RPC method to mine a new block
        // containing the specified transactions
        let address = self
            .inner
            .get_new_address(None, None)
            .unwrap()
            .assume_checked();
        for _ in 0..10 {
            let new_address = self
                .inner
                .get_new_address(None, None)
                .unwrap()
                .assume_checked();
            let amount = bitcoin::Amount::from_sat(1000); // Specify the amount to send
            self.inner
                .send_to_address(&new_address, amount, None, None, None, None, None, None)
                .unwrap();
        }
        self.inner.generate_to_address(1, &address).unwrap()
    }

    pub fn mine_blocks(&self, block_num: u64) {
        let new_address = self
            .inner
            .get_new_address(None, None)
            .unwrap()
            .assume_checked();
        self.inner
            .generate_to_address(block_num, &new_address)
            .unwrap();
    }

    pub fn send_to_address(&self, address: &Address, amount_sats: u64) -> OutPoint {
        let txid = self
            .inner
            .send_to_address(
                &address,
                Amount::from_sat(amount_sats),
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap_or_else(|e| panic!("Failed to send to address: {}", e));
        let tx_result = self
            .inner
            .get_transaction(&txid, None)
            .unwrap_or_else(|e| panic!("Failed to get transaction: {}", e));
        let vout = tx_result.details[0].vout;
        OutPoint { txid, vout }
    }

    pub fn get_work_at_block(&self, blockheight: u64) -> Work {
        let block_hash = self.inner.get_block_hash(blockheight).unwrap();
        let block = self.inner.get_block(&block_hash).unwrap();
        let work = block.header.work();
        work
    }

    pub fn calculate_total_work_between_blocks(&self, start: u64, end: u64) -> U256 {
        if start == end {
            return U256::from_be_bytes([0u8; 32]);
        }
        let mut total_work = Work::from_be_bytes([0u8; 32]);
        for i in start + 1..end + 1 {
            let work = self.get_work_at_block(i as u64);
            total_work = total_work + work;
        }
        let work_bytes = total_work.to_be_bytes();
        let res = U256::from_be_bytes(work_bytes);
        return res;
    }

    pub fn get_total_work_as_u256(&self) -> U256 {
        let chain_info = self.inner.get_blockchain_info().unwrap();
        let total_work_bytes = chain_info.chain_work;
        let total_work: U256 = U256::from_be_bytes(total_work_bytes.try_into().unwrap());
        return total_work;
    }

    pub fn get_total_work(&self) -> Work {
        let chain_info = self.inner.get_blockchain_info().unwrap();
        let total_work_bytes = chain_info.chain_work;
        let total_work: Work = Work::from_be_bytes(total_work_bytes.try_into().unwrap());
        return total_work;
    }

    pub fn get_block_height(&self) -> u64 {
        let chain_info = self.inner.get_blockchain_info().unwrap();
        let block_height = chain_info.blocks;
        return block_height;
    }

    // Following methods are just wrappers around the bitcoincore_rpc::Client methods
    pub fn get_blockchain_info(
        &self,
    ) -> Result<bitcoincore_rpc::json::GetBlockchainInfoResult, bitcoincore_rpc::Error> {
        self.inner.get_blockchain_info()
    }

    pub fn get_block_count(&self) -> Result<u64, bitcoincore_rpc::Error> {
        self.inner.get_block_count()
    }

    pub fn get_best_block_hash(&self) -> Result<bitcoin::BlockHash, bitcoincore_rpc::Error> {
        self.inner.get_best_block_hash()
    }

    pub fn get_raw_transaction(
        &self,
        txid: &bitcoin::Txid,
        block_hash: Option<&bitcoin::BlockHash>,
    ) -> Result<bitcoin::Transaction, bitcoincore_rpc::Error> {
        self.inner.get_raw_transaction(txid, block_hash)
    }

    pub fn get_transaction(
        &self,
        txid: &bitcoin::Txid,
        include_watchonly: Option<bool>,
    ) -> Result<bitcoincore_rpc::json::GetTransactionResult, bitcoincore_rpc::Error> {
        self.inner.get_transaction(txid, include_watchonly)
    }

    pub fn send_raw_transaction(
        &self,
        tx: &Transaction,
    ) -> Result<bitcoin::Txid, bitcoincore_rpc::Error> {
        self.inner.send_raw_transaction(tx)
    }

    pub fn get_block(
        &self,
        block_hash: &bitcoin::BlockHash,
    ) -> Result<bitcoin::Block, bitcoincore_rpc::Error> {
        self.inner.get_block(block_hash)
    }
}
