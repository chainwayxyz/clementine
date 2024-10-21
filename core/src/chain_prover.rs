//! # Header Chain Prover
//!
//! Fetches latest blocks from Bitcoin and prepares proves for them.

use crate::{
    config::BridgeConfig, database::Database, errors::BridgeError, extended_rpc::ExtendedRpc,
};
use bitcoin::block;
use bitcoin_mock_rpc::RpcApiWrapper;
use bitcoincore_rpc::json::GetChainTipsResultStatus;

#[derive(Debug, Clone)]
pub struct ChainProver<R>
where
    R: RpcApiWrapper,
{
    rpc: ExtendedRpc<R>,
    db: Database,
}

impl<R> ChainProver<R>
where
    R: RpcApiWrapper,
{
    pub async fn new(config: BridgeConfig, rpc: ExtendedRpc<R>) -> Result<Self, BridgeError> {
        let db = Database::new(&config).await?;

        Ok(ChainProver { rpc, db })
    }

    pub fn start_block_prover(&'static self) {
        tokio::spawn(async move {
            loop {
                let _ = self.fetch_new_blocks().await;
            }
        });
    }

    /// Checks for new blocks, that are not in current database. If not, writes
    /// it's details to database.
    async fn fetch_new_blocks(&self) -> Result<(), BridgeError> {
        // Return early if database is up to date.
        let db_tip_height = self.db.get_latest_chain_proof_height(None).await?;
        for tip in self.rpc.client.get_chain_tips()? {
            if tip.status == GetChainTipsResultStatus::Active && db_tip_height as u64 == tip.height
            {
                return Ok(());
            }
        }

        todo!()
    }

    pub async fn get_header_chain_proof(_height: u64, _block_hash: Option<block::BlockHash>) {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        chain_prover::ChainProver, create_extended_rpc, extended_rpc::ExtendedRpc,
        mock::common::get_test_config,
    };

    #[tokio::test]
    async fn new() {
        let mut config = get_test_config("test_config.toml").unwrap();
        let rpc = create_extended_rpc!(config);

        let _should_not_panic = ChainProver::new(config, rpc).await.unwrap();
    }
}
