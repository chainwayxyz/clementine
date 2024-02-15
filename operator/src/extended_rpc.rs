use bitcoincore_rpc::Auth;
use bitcoincore_rpc::Client;
use bitcoincore_rpc::RpcApi;

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
}
