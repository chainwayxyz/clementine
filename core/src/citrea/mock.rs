use super::CitreaClientT;
use crate::errors::BridgeError;
use alloy::signers::local::PrivateKeySigner;
use bitcoin::{hashes::Hash, OutPoint, Txid};
use std::{collections::hash_map, time::Duration};
use tonic::async_trait;

/// A mock implementation of the CitreaClientTrait. This implementation is used
/// for testing purposes and will generate dummy values. Don't use this in
/// citrea-e2e tests, use the real client.
#[derive(Clone, Debug, Default)]
pub struct MockCitreaClient {
    /// Deposit move txids for each height
    pub deposit_move_txids: hash_map::HashMap<u64, Vec<Txid>>,
    /// Withdrawal utxos and its indexes for each height
    pub withdrawal_utxos: hash_map::HashMap<u64, Vec<(u64, OutPoint)>>,
}

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

        Ok(MockCitreaClient::default())
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

        for i in from_height..to_height + 1 {
            if let Some(txids) = self.deposit_move_txids.get(&i) {
                for txid in txids {
                    ret.push((i, *txid));
                }
            }
        }

        Ok(ret)
    }

    async fn collect_withdrawal_utxos(
        &self,
        from_height: u64,
        to_height: u64,
    ) -> Result<Vec<(u64, OutPoint)>, BridgeError> {
        let mut ret = vec![];

        for i in from_height..to_height + 1 {
            if let Some(utxos) = self.withdrawal_utxos.get(&i) {
                for utxo in utxos {
                    ret.push((i, utxo.1));
                }
            }
        }

        Ok(ret)
    }

    async fn get_light_client_proof(
        &self,
        l1_height: u64,
    ) -> Result<Option<(u64, Vec<u8>)>, BridgeError> {
        Ok(Some((l1_height, vec![0; 32])))
    }

    async fn get_citrea_l2_height_range(
        &self,
        block_height: u64,
        _timeout: Duration,
    ) -> Result<(u64, u64), BridgeError> {
        Ok((block_height - 1, block_height))
    }
}

impl MockCitreaClient {
    /// Pushes a deposit move txid to the given height.
    pub fn push_deposit_move_txid(&mut self, height: u64, txid: Txid) {
        let mut txids = self
            .deposit_move_txids
            .get(&height)
            .unwrap_or(&Vec::<Txid>::new())
            .clone();
        txids.push(txid);

        self.deposit_move_txids.insert(height, txids);
    }

    /// Pushes a withdrawal utxo and its ondex to the given height.
    pub fn push_withdrawal_utxo(&mut self, height: u64, index: u64, utxo: OutPoint) {
        let mut utxos = self
            .withdrawal_utxos
            .get(&height)
            .unwrap_or(&Vec::<(u64, OutPoint)>::new())
            .clone();
        utxos.push((index, utxo));

        self.withdrawal_utxos.insert(height, utxos);
    }
}

#[cfg(test)]
mod tests {
    use crate::citrea::CitreaClientT;
    use bitcoin::hashes::Hash;

    #[tokio::test]
    async fn deposit_move_txid() {
        let mut client = super::MockCitreaClient::default();

        assert!(client
            .collect_deposit_move_txids(1, 2)
            .await
            .unwrap()
            .is_empty());

        client.push_deposit_move_txid(1, bitcoin::Txid::from_slice(&[1; 32]).unwrap());
        client.push_deposit_move_txid(1, bitcoin::Txid::from_slice(&[2; 32]).unwrap());
        client.push_deposit_move_txid(2, bitcoin::Txid::from_slice(&[3; 32]).unwrap());

        let txids = client.collect_deposit_move_txids(1, 2).await.unwrap();

        assert_eq!(txids.len(), 3);
        assert_eq!(txids[0].1, bitcoin::Txid::from_slice(&[1; 32]).unwrap());
        assert_eq!(txids[1].1, bitcoin::Txid::from_slice(&[2; 32]).unwrap());
        assert_eq!(txids[2].1, bitcoin::Txid::from_slice(&[3; 32]).unwrap());
    }

    #[tokio::test]
    async fn withdrawal_utxos() {
        let mut client = super::MockCitreaClient::default();

        assert!(client
            .collect_withdrawal_utxos(1, 2)
            .await
            .unwrap()
            .is_empty());

        client.push_withdrawal_utxo(
            1,
            0,
            bitcoin::OutPoint::new(bitcoin::Txid::from_slice(&[1; 32]).unwrap(), 0),
        );
        client.push_withdrawal_utxo(
            1,
            1,
            bitcoin::OutPoint::new(bitcoin::Txid::from_slice(&[2; 32]).unwrap(), 1),
        );
        client.push_withdrawal_utxo(
            2,
            2,
            bitcoin::OutPoint::new(bitcoin::Txid::from_slice(&[3; 32]).unwrap(), 2),
        );

        let utxos = client.collect_withdrawal_utxos(1, 2).await.unwrap();

        assert_eq!(utxos.len(), 3);
        assert_eq!(
            utxos[0].1,
            bitcoin::OutPoint::new(bitcoin::Txid::from_slice(&[1; 32]).unwrap(), 0)
        );
        assert_eq!(
            utxos[1].1,
            bitcoin::OutPoint::new(bitcoin::Txid::from_slice(&[2; 32]).unwrap(), 1)
        );
        assert_eq!(
            utxos[2].1,
            bitcoin::OutPoint::new(bitcoin::Txid::from_slice(&[3; 32]).unwrap(), 2)
        );
    }
}
