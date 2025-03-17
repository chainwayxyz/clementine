use super::CitreaClientT;
use crate::{
    database::{DatabaseTransaction, OutPointDB, TxidDB},
    errors::BridgeError,
    execute_query_with_tx,
};
use alloy::signers::local::PrivateKeySigner;
use bitcoin::{OutPoint, Txid};
use sqlx::{Pool, Postgres};
use std::time::Duration;
use tonic::async_trait;

/// A mock implementation of the CitreaClientTrait. This implementation is used
/// for testing purposes and will generate dummy values. Don't use this in
/// citrea-e2e tests, use the real client.
#[derive(Clone, Debug)]
pub struct MockCitreaClient {
    connection: Pool<Postgres>,
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
        tracing::warn!(
            "Using the mock Citrea client, beware that data returned from this client is not real"
        );

        tracing::debug!("Connecting to the database: {}", citrea_rpc_url);

        Ok(MockCitreaClient {
            connection: sqlx::PgPool::connect(&citrea_rpc_url).await.unwrap(),
        })
    }

    async fn withdrawal_utxos(&self, withdrawal_index: u64) -> Result<OutPoint, BridgeError> {
        let query = sqlx::query_as(
            "SELECT utxo
            FROM withdrawals
            WHERE idx = $1",
        )
        .bind(i64::try_from(withdrawal_index).unwrap());

        let utxo: (OutPointDB,) = execute_query_with_tx!(
            self.connection,
            None::<DatabaseTransaction>,
            query,
            fetch_one
        )?;

        Ok(utxo.0 .0)
    }

    async fn collect_deposit_move_txids(
        &self,
        from_height: u64,
        to_height: u64,
    ) -> Result<Vec<(u64, Txid)>, BridgeError> {
        let mut ret: Vec<(u64, Txid)> = vec![];

        for i in from_height..to_height + 1 {
            let query = sqlx::query_as(
                "SELECT idx, move_txid
                FROM deposits
                WHERE height = $1",
            )
            .bind(i64::try_from(i).unwrap());

            let results: Vec<(i32, TxidDB)> = execute_query_with_tx!(
                self.connection,
                None::<DatabaseTransaction>,
                query,
                fetch_all
            )?;

            for result in results {
                ret.push((result.0 as u64, result.1 .0));
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
            let query = sqlx::query_as(
                "SELECT idx, utxo
                FROM withdrawals
                WHERE height = $1",
            )
            .bind(i64::try_from(i).unwrap());

            let results: Vec<(i32, OutPointDB)> = execute_query_with_tx!(
                self.connection,
                None::<DatabaseTransaction>,
                query,
                fetch_all
            )?;
            for result in results {
                ret.push((result.0 as u64 - 1, result.1 .0)); // TODO: Remove -1 when Bridge contract is fixed
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
    pub async fn insert_deposit_move_txid(&mut self, height: u64, txid: Txid) {
        let query = sqlx::query("INSERT INTO deposits (height, move_txid) VALUES ($1, $2)")
            .bind(i64::try_from(height).unwrap())
            .bind(TxidDB(txid));

        execute_query_with_tx!(self.connection, None::<DatabaseTransaction>, query, execute)
            .unwrap();
    }

    /// Pushes a withdrawal utxo and its ondex to the given height.
    /// TODO: Make it calc index auto
    pub async fn insert_withdrawal_utxo(&mut self, height: u64, utxo: OutPoint) {
        let query = sqlx::query("INSERT INTO withdrawals (height, utxo) VALUES ($1, $2)")
            .bind(i64::try_from(height).unwrap())
            .bind(OutPointDB(utxo));

        execute_query_with_tx!(self.connection, None::<DatabaseTransaction>, query, execute)
            .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        citrea::CitreaClientT,
        test::common::{citrea, create_test_config_with_thread_name},
    };
    use bitcoin::hashes::Hash;

    #[tokio::test]
    async fn deposit_move_txid() {
        let mut config = create_test_config_with_thread_name(None).await;
        citrea::create_mock_citrea_database(&mut config).await;
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
        let mut config = create_test_config_with_thread_name(None).await;
        citrea::create_mock_citrea_database(&mut config).await;
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

        let utxo_from_index = client.withdrawal_utxos(1).await.unwrap();
        assert_eq!(
            utxo_from_index,
            bitcoin::OutPoint::new(bitcoin::Txid::from_slice(&[2; 32]).unwrap(), 1)
        );
    }
}
