use bitcoincore_rpc::Client;
use bitcoincore_rpc::RpcApi;

struct ExtendedRpc {
    pub inner: Client,
}

impl ExtendedRpc {
    pub fn new(client: Client) -> Self {
        Self { inner: client }
    }

    pub fn generate_dummy_block(&self) -> Vec<bitcoin::BlockHash> {
        // Use `generatetoaddress` or similar RPC method to mine a new block
        // containing the specified transactions
        let address = self.inner.get_new_address(None, None).unwrap().assume_checked();
        for _ in 0..10 {
            let new_address = self.inner.get_new_address(None, None).unwrap().assume_checked();
            let amount = bitcoin::Amount::from_sat(1000); // Specify the amount to send
            self.inner.send_to_address(&new_address, amount, None, None, None, None, None, None)
                .unwrap();
        }
        self.inner.generate_to_address(1, &address).unwrap()
    }
}