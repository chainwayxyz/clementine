//! # Header Chain Prover
//!
//! Fetches latest blocks from Bitcoin and prepares proves for them.

use crate::{
    config::BridgeConfig, database::Database, errors::BridgeError, extended_rpc::ExtendedRpc,
};
use bitcoin_mock_rpc::RpcApiWrapper;

#[derive(Debug, Clone)]
pub struct ChainProver<R>
where
    R: RpcApiWrapper,
{
    rpc: ExtendedRpc<R>,
    db: Database,
    config: BridgeConfig,
}

impl<R> ChainProver<R>
where
    R: RpcApiWrapper,
{
    pub async fn new(config: BridgeConfig, rpc: ExtendedRpc<R>) -> Result<Self, BridgeError> {
        let db = Database::new(&config).await?;

        Ok(ChainProver { rpc, db, config })
    }

    /// Checks for new blocks, that are not in current database. If not, writes
    /// it's details to database.
    ///
    /// This function won't return and run forever.
    async fn check_for_new_blocks(&self) {
        loop {}
    }

    pub async fn get_header_chain_proof(blocknum: u32) {
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
