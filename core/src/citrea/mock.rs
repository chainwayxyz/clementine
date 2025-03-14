use super::CitreaClientTrait;
use crate::errors::BridgeError;
use alloy::signers::local::PrivateKeySigner;
use bitcoin::{hashes::Hash, OutPoint, Txid};
use std::marker::PhantomData;
use tonic::async_trait;

/// A mock implementation of the CitreaClientTrait. This implementation is used
/// for testing purposes and will generate dummy values.
#[derive(Clone, Debug)]
pub struct MockCitreaClient {
    data: PhantomData<()>,
}

#[async_trait]
impl CitreaClientTrait for MockCitreaClient {
    type Client = MockCitreaClient;

    fn new(
        _citrea_rpc_url: String,
        _light_client_prover_url: String,
        _secret_key: Option<PrivateKeySigner>,
    ) -> Result<Self::Client, BridgeError> {
        Ok(MockCitreaClient { data: PhantomData })
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
}
