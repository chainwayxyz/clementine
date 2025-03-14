use super::CitreaClientT;
use crate::errors::BridgeError;
use alloy::signers::local::PrivateKeySigner;
use bitcoin::{hashes::Hash, OutPoint, Txid};
use std::time::Duration;
use tonic::async_trait;

/// A mock implementation of the CitreaClientTrait. This implementation is used
/// for testing purposes and will generate dummy values. Don't use this in
/// citrea-e2e tests, use the real client.
#[derive(Clone, Debug)]
pub struct MockCitreaClient;

#[async_trait]
impl CitreaClientT for MockCitreaClient {
    fn new(
        _citrea_rpc_url: String,
        _light_client_prover_url: String,
        _secret_key: Option<PrivateKeySigner>,
    ) -> Result<Self, BridgeError> {
        tracing::warn!(
            "Using the mock Citrea client, beware that data returned from this client is not real"
        );

        Ok(MockCitreaClient)
    }

    async fn withdrawal_utxos(&self, withdrawal_index: u64) -> Result<OutPoint, BridgeError> {
        Ok(OutPoint {
            txid: Txid::all_zeros(),
            vout: withdrawal_index as u32,
        })
    }

    async fn collect_deposit_move_txids(
        &self,
        from_height: u64,
        to_height: u64,
    ) -> Result<Vec<(u64, Txid)>, BridgeError> {
        let mut ret = vec![];

        for i in from_height..to_height {
            let txid = Txid::from_slice(&[i as u8; 32]).unwrap();
            ret.push((i, txid));
        }

        Ok(ret)
    }

    async fn collect_withdrawal_utxos(
        &self,
        from_height: u64,
        to_height: u64,
    ) -> Result<Vec<(u64, OutPoint)>, BridgeError> {
        let mut ret = vec![];

        for i in from_height..to_height {
            let txid = Txid::from_slice(&[i as u8; 32]).unwrap();
            let outpoint = OutPoint {
                txid,
                vout: i as u32,
            };
            ret.push((i, outpoint));
        }

        Ok(ret)
    }

    async fn get_light_client_proof(
        &self,
        _l1_height: u64,
    ) -> Result<Option<(u64, Vec<u8>)>, BridgeError> {
        Ok(None)
    }

    async fn get_citrea_l2_height_range(
        &self,
        block_height: u64,
        _timeout: Duration,
    ) -> Result<(u64, u64), BridgeError> {
        Ok((block_height, block_height))
    }
}
