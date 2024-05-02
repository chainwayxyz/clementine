use async_trait::async_trait;
use bitcoin::{Address, OutPoint};
use secp256k1::XOnlyPublicKey;

use crate::{errors::BridgeError, operator::DepositPresigns, EVMAddress};

#[async_trait]
pub trait VerifierConnector: std::fmt::Debug + Send + Sync {
    async fn new_deposit(
        &self,
        start_utxo: OutPoint,
        return_address: &XOnlyPublicKey,
        deposit_index: u32,
        evm_address: &EVMAddress,
        operator_address: &Address,
    ) -> Result<DepositPresigns, BridgeError>;

    #[cfg(feature = "poc")]
    fn connector_roots_created(
        &self,
        connector_tree_hashes: &Vec<Vec<Vec<[u8; 32]>>>,
        first_source_utxo: &OutPoint,
        start_blockheight: u64,
        period_relative_block_heights: Vec<u32>,
    ) -> Result<(), BridgeError>;

    #[cfg(feature = "poc")]
    fn challenge_operator(&self, period: u8) -> Result<VerifierChallenge, BridgeError>;
}
