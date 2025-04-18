use super::CitreaClientT;
use crate::errors::BridgeError;
use alloy::signers::local::PrivateKeySigner;
use bitcoin::{OutPoint, Txid};
use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, LazyLock, Weak},
    time::Duration,
};
use tokio::sync::{Mutex, MutexGuard};
use tonic::async_trait;

pub struct Deposit {
    idx: u64,
    height: u64,
    move_txid: Txid,
}

pub struct Withdrawal {
    idx: u64,
    height: u64,
    utxo: OutPoint,
}

pub struct MockCitreaStorage {
    #[allow(dead_code)]
    name: String,
    deposits: Vec<Deposit>,
    withdrawals: Vec<Withdrawal>,
}

impl MockCitreaStorage {
    pub fn new(name: String) -> Self {
        Self {
            name,
            deposits: vec![],
            withdrawals: vec![],
        }
    }
}

#[allow(clippy::type_complexity)]
pub static MOCK_CITREA_GLOBAL: LazyLock<
    Arc<Mutex<HashMap<String, Weak<Mutex<MockCitreaStorage>>>>>,
> = LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));

/// A mock implementation of the CitreaClientTrait. This implementation is used
/// for testing purposes and will generate dummy values. Don't use this in
/// citrea-e2e tests, use the real client.
#[derive(Clone)]
pub struct MockCitreaClient {
    storage: Arc<Mutex<MockCitreaStorage>>,
}

impl std::fmt::Debug for MockCitreaClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MockCitreaClient")
    }
}

impl MockCitreaClient {
    pub async fn get_storage(&self) -> MutexGuard<'_, MockCitreaStorage> {
        self.storage.lock().await
    }
}

#[async_trait]
impl CitreaClientT for MockCitreaClient {
    /// Connects a database with the given URL which is stored in
    /// `citrea_rpc_url`. Other paramaters are dumped.
    async fn new(
        citrea_rpc_url: String,
        _light_client_prover_url: String,
        _secret_key: Option<PrivateKeySigner>,
    ) -> Result<Self, BridgeError> {
        tracing::info!(
            "Using the mock Citrea client ({citrea_rpc_url}), beware that data returned from this client is not real"
        );
        if citrea_rpc_url.is_empty() {
            return Err(eyre::eyre!(
                "citrea_rpc_url is empty, please use create_mock_citrea_database to create a mock citrea client"
            )
            .into());
        }

        let mut global = MOCK_CITREA_GLOBAL.lock().await;
        if global.contains_key(&citrea_rpc_url) {
            let storage = global
                .get(&citrea_rpc_url)
                .unwrap()
                .upgrade()
                .expect("Storage dropped during test");
            Ok(MockCitreaClient { storage })
        } else {
            let storage = Arc::new(Mutex::new(MockCitreaStorage::new(citrea_rpc_url.clone())));
            global.insert(citrea_rpc_url.clone(), Arc::downgrade(&storage));
            Ok(MockCitreaClient { storage })
        }
    }

    async fn withdrawal_utxos(&self, withdrawal_index: u64) -> Result<OutPoint, BridgeError> {
        Ok(*self
            .get_storage()
            .await
            .withdrawals
            .iter()
            .find_map(|Withdrawal { idx, utxo, .. }| {
                if *idx == withdrawal_index {
                    Some(utxo)
                } else {
                    None
                }
            })
            .unwrap())
    }

    async fn collect_deposit_move_txids(
        &self,
        from_height: u64,
        to_height: u64,
    ) -> Result<Vec<(u64, Txid)>, BridgeError> {
        let mut ret: Vec<(u64, Txid)> = vec![];

        for i in from_height..to_height + 1 {
            let storage = self.storage.lock().await;
            let results: Vec<(i32, Txid)> = storage
                .deposits
                .iter()
                .filter(|deposit| deposit.height == i)
                .map(|deposit| (deposit.idx as i32, deposit.move_txid))
                .collect();

            for result in results {
                ret.push((result.0 as u64, result.1));
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
            let storage = self.storage.lock().await;
            let results: Vec<(i32, OutPoint)> = storage
                .withdrawals
                .iter()
                .filter(|withdrawal| withdrawal.height == i)
                .map(|withdrawal| (withdrawal.idx as i32, withdrawal.utxo))
                .collect();
            for result in results {
                ret.push((result.0 as u64 - 1, result.1)); // TODO: Remove -1 when Bridge contract is fixed
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
        Ok((if block_height == 0 { 0 } else { block_height - 1 }, block_height))
    }

    async fn check_nofn_correctness(
        &self,
        _nofn_xonly_pk: bitcoin::XOnlyPublicKey,
    ) -> Result<(), BridgeError> {
        Ok(())
    }
}

impl MockCitreaClient {
    /// Pushes a deposit move txid to the given height.
    pub async fn insert_deposit_move_txid(&mut self, height: u64, txid: Txid) {
        let mut storage = self.storage.lock().await;
        let idx = storage.deposits.len() as u64 + 1;
        storage.deposits.push(Deposit {
            idx,
            height,
            move_txid: txid,
        });
    }

    /// Pushes a withdrawal utxo and its index to the given height.
    pub async fn insert_withdrawal_utxo(&mut self, height: u64, utxo: OutPoint) {
        let mut storage = self.storage.lock().await;
        let idx = storage.withdrawals.len() as u64 + 1;
        storage.withdrawals.push(Withdrawal { idx, height, utxo });
    }
}

#[cfg(test)]
mod tests {
    use crate::{citrea::CitreaClientT, test::common::create_test_config_with_thread_name};
    use bitcoin::hashes::Hash;

    #[tokio::test]
    async fn deposit_move_txid() {
        let config = create_test_config_with_thread_name().await;
        let mut client = super::MockCitreaClient::new(config.citrea_rpc_url, "".to_string(), None)
            .await
            .unwrap();

        assert!(client
            .collect_deposit_move_txids(1, 2)
            .await
            .unwrap()
            .is_empty());

        client
            .insert_deposit_move_txid(1, bitcoin::Txid::from_slice(&[1; 32]).unwrap())
            .await;
        client
            .insert_deposit_move_txid(1, bitcoin::Txid::from_slice(&[2; 32]).unwrap())
            .await;
        client
            .insert_deposit_move_txid(2, bitcoin::Txid::from_slice(&[3; 32]).unwrap())
            .await;

        let txids = client.collect_deposit_move_txids(1, 2).await.unwrap();

        assert_eq!(txids.len(), 3);
        assert_eq!(txids[0].1, bitcoin::Txid::from_slice(&[1; 32]).unwrap());
        assert_eq!(txids[1].1, bitcoin::Txid::from_slice(&[2; 32]).unwrap());
        assert_eq!(txids[2].1, bitcoin::Txid::from_slice(&[3; 32]).unwrap());
    }

    #[tokio::test]
    async fn withdrawal_utxos() {
        let config = create_test_config_with_thread_name().await;
        let mut client = super::MockCitreaClient::new(config.citrea_rpc_url, "".to_string(), None)
            .await
            .unwrap();

        assert!(client
            .collect_withdrawal_utxos(1, 2)
            .await
            .unwrap()
            .is_empty());

        client
            .insert_withdrawal_utxo(
                1,
                bitcoin::OutPoint::new(bitcoin::Txid::from_slice(&[1; 32]).unwrap(), 0),
            )
            .await;
        client
            .insert_withdrawal_utxo(
                1,
                bitcoin::OutPoint::new(bitcoin::Txid::from_slice(&[2; 32]).unwrap(), 1),
            )
            .await;
        client
            .insert_withdrawal_utxo(
                2,
                bitcoin::OutPoint::new(bitcoin::Txid::from_slice(&[3; 32]).unwrap(), 2),
            )
            .await;

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

        // TODO: Fix Remove +1 when Bridge contract is fixed
        let utxo_from_index = client.withdrawal_utxos(1 + 1).await.unwrap();
        assert_eq!(
            utxo_from_index,
            bitcoin::OutPoint::new(bitcoin::Txid::from_slice(&[2; 32]).unwrap(), 1)
        );
    }
}
