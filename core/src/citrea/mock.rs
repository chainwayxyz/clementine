use crate::errors::BridgeError;
use alloy::{signers::local::PrivateKeySigner, transports::http::reqwest::Url};
use bitcoin::{OutPoint, Txid};
use std::marker::PhantomData;
use tonic::async_trait;

use super::CitreaClientTrait;

#[derive(Clone, Debug)]
pub struct MockCitreaClient {
    data: PhantomData<()>,
}

#[async_trait]
impl CitreaClientTrait for MockCitreaClient {
    type Client = MockCitreaClient;

    fn new(
        citrea_rpc_url: Url,
        light_client_prover_url: Url,
        secret_key: Option<PrivateKeySigner>,
    ) -> Result<Self::Client, BridgeError> {
        todo!()
    }

    async fn withdrawal_utxos(&self, withdrawal_index: u64) -> Result<OutPoint, BridgeError> {
        todo!()
    }

    async fn collect_deposit_move_txids(
        &self,
        from_height: u64,
        to_height: u64,
    ) -> Result<Vec<(u64, Txid)>, BridgeError> {
        todo!()
    }

    async fn collect_withdrawal_utxos(
        &self,
        from_height: u64,
        to_height: u64,
    ) -> Result<Vec<(u64, OutPoint)>, BridgeError> {
        todo!()
    }
}
