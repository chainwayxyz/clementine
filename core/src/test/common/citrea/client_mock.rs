use crate::{
    citrea::CitreaClientT,
    config::protocol::ProtocolParamset,
    database::{Database, DatabaseTransaction},
};
use alloy::signers::local::PrivateKeySigner;
use bitcoin::{OutPoint, Txid};
use circuits_lib::bridge_circuit::structs::{LightClientProof, StorageProof};
use clementine_errors::BridgeError;
use eyre::Context;
use risc0_zkvm::Receipt;
use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, LazyLock, Weak},
    time::Duration,
};
use tokio::sync::{Mutex, MutexGuard};
use tonic::async_trait;

pub struct Deposit {
    idx: u32,
    height: u64,
    move_txid: Txid,
}

pub struct Withdrawal {
    idx: u32,
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
    async fn get_storage_proof(
        &self,
        _l2_height: u64,
        deposit_index: u32,
    ) -> Result<StorageProof, BridgeError> {
        Ok(StorageProof {
            storage_proof_utxo: "".to_string(),
            storage_proof_vout: "".to_string(),
            storage_proof_deposit_txid: "".to_string(),
            index: deposit_index,
        })
    }

    async fn fetch_validate_and_store_lcp(
        &self,
        _payout_block_height: u64,
        _deposit_index: u32,
        _db: &Database,
        _dbtx: Option<DatabaseTransaction<'_>>,
        _paramset: &'static ProtocolParamset,
    ) -> Result<Receipt, BridgeError> {
        Ok(borsh::from_slice(include_bytes!(
            "../../../../../circuits-lib/test_data/lcp_receipt.bin"
        ))
        .wrap_err("Couldn't create mock receipt")?)
    }
    /// Connects a database with the given URL which is stored in
    /// `citrea_rpc_url`. Other parameters are dumped.
    async fn new(
        citrea_rpc_url: String,
        _light_client_prover_url: String,
        _chain_id: u32,
        _secret_key: Option<PrivateKeySigner>,
        _timeout: Option<Duration>,
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

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::DEBUG))]
    async fn collect_deposit_move_txids(
        &self,
        last_deposit_idx: Option<u32>,
        to_height: u64,
    ) -> Result<Vec<(u64, Txid)>, BridgeError> {
        let storage = self.storage.lock().await;
        let start_idx = match last_deposit_idx {
            Some(idx) => idx + 1,
            None => 0,
        };

        let results: Vec<(u64, Txid)> = storage
            .deposits
            .iter()
            .filter(|deposit| deposit.height <= to_height && deposit.idx >= start_idx)
            .map(|deposit| (deposit.idx as u64, deposit.move_txid))
            .collect();

        Ok(results)
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::DEBUG))]
    async fn collect_withdrawal_utxos(
        &self,
        last_withdrawal_idx: Option<u32>,
        to_height: u64,
    ) -> Result<Vec<(u64, OutPoint)>, BridgeError> {
        let storage = self.storage.lock().await;
        let start_idx = match last_withdrawal_idx {
            Some(idx) => idx + 1,
            None => 0,
        };

        let results: Vec<(u64, OutPoint)> = storage
            .withdrawals
            .iter()
            .filter(|withdrawal| withdrawal.height <= to_height && withdrawal.idx >= start_idx)
            .map(|withdrawal| (withdrawal.idx as u64, withdrawal.utxo))
            .collect();

        Ok(results)
    }

    async fn get_light_client_proof(
        &self,
        l1_height: u64,
        _paramset: &'static ProtocolParamset,
    ) -> Result<Option<(LightClientProof, Receipt, u64)>, BridgeError> {
        Ok(Some((
            LightClientProof { lc_journal: vec![] },
            borsh::from_slice(include_bytes!(
                "../../../../../circuits-lib/test_data/lcp_receipt.bin"
            ))
            .wrap_err("Couldn't create mock receipt")?,
            l1_height,
        )))
    }

    async fn get_citrea_l2_height_range(
        &self,
        block_height: u64,
        _timeout: Duration,
        _paramset: &'static ProtocolParamset,
    ) -> Result<(u64, u64), BridgeError> {
        Ok((
            if block_height == 0 {
                0
            } else {
                block_height - 1
            },
            block_height,
        ))
    }

    async fn get_replacement_deposit_move_txids(
        &self,
        _from_height: u64,
        _to_height: u64,
    ) -> Result<Vec<(u32, Txid)>, BridgeError> {
        Ok(vec![])
    }

    async fn check_nofn_correctness(
        &self,
        _nofn_xonly_pk: bitcoin::XOnlyPublicKey,
    ) -> Result<(), BridgeError> {
        Ok(())
    }

    async fn get_current_l2_block_height(&self) -> Option<u32> {
        None
    }
}

impl MockCitreaClient {
    /// Pushes a deposit move txid to the given height.
    pub async fn insert_deposit_move_txid(&mut self, height: u64, txid: Txid) {
        let mut storage = self.storage.lock().await;
        let idx = storage.deposits.len() as u32;

        tracing::debug!("Inserting deposit move txid {txid:?} at height {height} with index {idx}");
        storage.deposits.push(Deposit {
            idx,
            height,
            move_txid: txid,
        });
    }

    /// Pushes a withdrawal utxo and its index to the given height.
    pub async fn insert_withdrawal_utxo(&mut self, height: u64, utxo: OutPoint) {
        let mut storage = self.storage.lock().await;
        let idx = storage.withdrawals.len() as u32;

        tracing::debug!("Inserting withdrawal utxo {utxo:?} at height {height} with index {idx}");
        storage.withdrawals.push(Withdrawal { idx, height, utxo });
    }
}

#[cfg(all(test, feature = "integration-tests"))]
mod tests {
    use crate::{citrea::CitreaClientT, test::common::create_test_config_with_thread_name};
    use bitcoin::hashes::Hash;

    #[tokio::test]
    async fn deposit_move_txid() {
        let config = create_test_config_with_thread_name().await;
        let mut client = super::MockCitreaClient::new(
            config.citrea_rpc_url,
            "".to_string(),
            config.citrea_chain_id,
            None,
            None,
        )
        .await
        .unwrap();

        assert!(client
            .collect_deposit_move_txids(None, 2)
            .await
            .unwrap()
            .is_empty());

        client
            .insert_deposit_move_txid(1, bitcoin::Txid::from_slice(&[1; 32]).unwrap())
            .await;
        client
            .insert_deposit_move_txid(1, bitcoin::Txid::from_slice(&[2; 32]).unwrap())
            .await;

        let txids = client.collect_deposit_move_txids(None, 1).await.unwrap();
        assert_eq!(txids.len(), 2);
        assert_eq!(txids[0].1, bitcoin::Txid::from_slice(&[1; 32]).unwrap());

        let txids = client.collect_deposit_move_txids(Some(0), 2).await.unwrap();
        assert_eq!(txids.len(), 1);
        assert_eq!(txids[0].1, bitcoin::Txid::from_slice(&[2; 32]).unwrap());

        // Idx 1 is not available till height 2 (0 indexed).
        assert!(client
            .collect_deposit_move_txids(Some(0), 0)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn withdrawal_utxos() {
        let config = create_test_config_with_thread_name().await;
        let mut client = super::MockCitreaClient::new(
            config.citrea_rpc_url,
            "".to_string(),
            config.citrea_chain_id,
            None,
            None,
        )
        .await
        .unwrap();

        assert!(client
            .collect_withdrawal_utxos(None, 2)
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

        let utxos = client.collect_withdrawal_utxos(None, 2).await.unwrap();
        assert_eq!(utxos.len(), 2);
        assert_eq!(
            utxos[0].1,
            bitcoin::OutPoint::new(bitcoin::Txid::from_slice(&[1; 32]).unwrap(), 0)
        );

        let utxos = client.collect_withdrawal_utxos(Some(0), 2).await.unwrap();
        assert_eq!(utxos.len(), 1);
        assert_eq!(
            utxos[0].1,
            bitcoin::OutPoint::new(bitcoin::Txid::from_slice(&[2; 32]).unwrap(), 1)
        );
    }
}
