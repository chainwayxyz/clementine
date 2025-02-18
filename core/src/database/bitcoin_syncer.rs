use super::{
    wrapper::{BlockHashDB, TxidDB},
    Database, DatabaseTransaction,
};
use crate::{bitcoin_syncer::BitcoinSyncerEvent, errors::BridgeError, execute_query_with_tx};
use bitcoin::{BlockHash, OutPoint, Txid};
use std::ops::DerefMut;

impl Database {
    /// # Returns
    ///
    /// - [`u32`]: Database entry id, later to be used while referring block
    pub async fn add_block_info(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        block_hash: &BlockHash,
        prev_block_hash: &BlockHash,
        block_height: i64,
    ) -> Result<u32, BridgeError> {
        let query = sqlx::query_scalar(
            "INSERT INTO bitcoin_syncer (blockhash, prev_blockhash, height) VALUES ($1, $2, $3) RETURNING id",
        )
        .bind(BlockHashDB(*block_hash))
        .bind(BlockHashDB(*prev_block_hash))
        .bind(block_height);

        let id: i32 = execute_query_with_tx!(self.connection, tx, query, fetch_one)?;

        Ok(id as u32)
    }
    /// # Returns
    ///
    /// [`Some`] if the block exists in the database, [`None`] otherwise:
    ///
    /// - [`BlockHash`]: Previous block hash
    /// - [`u32`]: Height of the block
    pub async fn get_block_info_from_hash(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        block_hash: BlockHash,
    ) -> Result<Option<(BlockHash, u32)>, BridgeError> {
        let query = sqlx::query_as(
            "SELECT prev_blockhash, height FROM bitcoin_syncer WHERE blockhash = $1 AND is_canonical = true",
        )
        .bind(BlockHashDB(block_hash));

        let ret: Option<(BlockHashDB, i64)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

        Ok(ret.map(|(prev_hash, height)| (prev_hash.0, height as u32)))
    }

    pub async fn get_block_info_from_id(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        block_id: u32,
    ) -> Result<Option<(BlockHash, u32)>, BridgeError> {
        let query = sqlx::query_as(
            "SELECT blockhash, height FROM bitcoin_syncer WHERE id = $1 AND is_canonical = true",
        )
        .bind(block_id as i32);

        let ret: Option<(BlockHashDB, i64)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

        Ok(ret.map(|(block_hash, height)| (block_hash.0, height as u32)))
    }

    pub async fn get_max_height(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
    ) -> Result<Option<u64>, BridgeError> {
        let query =
            sqlx::query_as("SELECT height FROM bitcoin_syncer WHERE is_canonical = true ORDER BY height DESC LIMIT 1");
        let result: Option<(i64,)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

        Ok(result.map(|(height,)| height as u64))
    }

    /// Gets the block hashes that have height bigger then the given height and deletes them.
    pub async fn set_non_canonical_block_hashes(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        height: u64,
    ) -> Result<Vec<i32>, BridgeError> {
        let query = sqlx::query_as(
            "WITH deleted AS (
                UPDATE bitcoin_syncer 
                SET is_canonical = false 
                WHERE height > $1 
                RETURNING id
            ) SELECT id FROM deleted",
        )
        .bind(height as i64);

        let block_ids: Vec<(i32,)> = execute_query_with_tx!(self.connection, tx, query, fetch_all)?;
        Ok(block_ids.into_iter().map(|(block_id,)| block_id).collect())
    }

    pub async fn add_txid_to_block(
        &self,
        tx: DatabaseTransaction<'_, '_>,
        block_id: u32,
        txid: &bitcoin::Txid,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query("INSERT INTO bitcoin_syncer_txs (block_id, txid) VALUES ($1, $2)")
            .bind(block_id as i32)
            .bind(super::wrapper::TxidDB(*txid));

        execute_query_with_tx!(self.connection, Some(tx), query, execute)?;

        Ok(())
    }
    pub async fn get_block_txids(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        block_id: u32,
    ) -> Result<Vec<Txid>, BridgeError> {
        let query = sqlx::query_as("SELECT txid FROM bitcoin_syncer_txs WHERE block_id = $1")
            .bind(block_id as i32);

        let txids: Vec<(TxidDB,)> = execute_query_with_tx!(self.connection, tx, query, fetch_all)?;

        Ok(txids.into_iter().map(|(txid,)| txid.0).collect())
    }

    pub async fn insert_spent_utxo(
        &self,
        tx: DatabaseTransaction<'_, '_>,
        block_id: u32,
        spending_txid: &bitcoin::Txid,
        txid: &bitcoin::Txid,
        vout: i64,
    ) -> Result<(), BridgeError> {
        sqlx::query(
            "INSERT INTO bitcoin_syncer_spent_utxos (block_id, spending_txid, txid, vout) VALUES ($1, $2, $3, $4)",
        )
        .bind(block_id as i32)
        .bind(super::wrapper::TxidDB(*spending_txid))
        .bind(super::wrapper::TxidDB(*txid))
        .bind(vout)
        .execute(tx.deref_mut())
        .await?;
        Ok(())
    }
    pub async fn get_spent_utxos_for_txid(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        txid: Txid,
    ) -> Result<Vec<(i64, OutPoint)>, BridgeError> {
        let query = sqlx::query_as(
            "SELECT block_id, txid, vout FROM bitcoin_syncer_spent_utxos WHERE spending_txid = $1",
        )
        .bind(TxidDB(txid));

        let spent_utxos: Vec<(i64, TxidDB, i64)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_all)?;

        Ok(spent_utxos
            .into_iter()
            .map(|(block_id, txid, vout)| {
                (
                    block_id,
                    OutPoint {
                        txid: txid.0,
                        vout: vout as u32,
                    },
                )
            })
            .collect())
    }

    pub async fn add_event(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        event_type: BitcoinSyncerEvent,
    ) -> Result<(), BridgeError> {
        let query = match event_type {
            BitcoinSyncerEvent::NewBlock(block_id) => sqlx::query(
                "INSERT INTO bitcoin_syncer_events (block_id, event_type) VALUES ($1, 'new_block'::bitcoin_syncer_event_type)",
            )
            .bind(block_id as i32),
            BitcoinSyncerEvent::ReorgedBlock(block_id) => sqlx::query(
                "INSERT INTO bitcoin_syncer_events (block_id, event_type) VALUES ($1, 'reorged_block'::bitcoin_syncer_event_type)",
            )
            .bind(block_id as i32),
        };
        execute_query_with_tx!(self.connection, tx, query, execute)?;
        Ok(())
    }

    pub async fn get_event_and_update(
        &self,
        tx: DatabaseTransaction<'_, '_>,
        consumer_handle: &str,
    ) -> Result<Option<BitcoinSyncerEvent>, BridgeError> {
        // Step 1: Insert the consumer_handle if it doesn't exist
        sqlx::query(
            r#"
            INSERT INTO bitcoin_syncer_event_handlers (consumer_handle, last_processed_event_id)
            VALUES ($1, 0)
            ON CONFLICT (consumer_handle) DO NOTHING
            "#,
        )
        .bind(consumer_handle)
        .execute(tx.deref_mut())
        .await?;

        // Step 2: Get the last processed event ID for this consumer
        let last_processed_event_id: i32 = sqlx::query_scalar(
            r#"
            SELECT last_processed_event_id
            FROM bitcoin_syncer_event_handlers
            WHERE consumer_handle = $1
            "#,
        )
        .bind(consumer_handle)
        .fetch_one(tx.deref_mut())
        .await?;

        // Step 3: Retrieve the next event that hasn't been processed yet
        let event = sqlx::query_as::<_, (i32, i32, String)>(
            r#"
            SELECT id, block_id, event_type::text
            FROM bitcoin_syncer_events
            WHERE id > $1
            ORDER BY id ASC
            LIMIT 1
            "#,
        )
        .bind(last_processed_event_id)
        .fetch_optional(tx.deref_mut())
        .await?;

        if event.is_none() {
            return Ok(None);
        }

        let event = event.expect("should exist since we checked is_none()");
        let event_type = match event.2.as_str() {
            "new_block" => BitcoinSyncerEvent::NewBlock(event.1 as u32),
            "reorged_block" => BitcoinSyncerEvent::ReorgedBlock(event.1 as u32),
            _ => return Err(BridgeError::Error("Invalid event type".to_string())),
        };
        let event_id = event.0;

        // Step 5: Update last_processed_event_id for this consumer
        sqlx::query(
            r#"
            UPDATE bitcoin_syncer_event_handlers
            SET last_processed_event_id = $1
            WHERE consumer_handle = $2
            "#,
        )
        .bind(event_id)
        .bind(consumer_handle)
        .execute(tx.deref_mut())
        .await?;

        Ok(Some(event_type))
    }
}

#[cfg(test)]
mod tests {
    use crate::{config::BridgeConfig, initialize_database, utils::initialize_logger};
    use crate::{create_test_config_with_thread_name, database::Database};
    use bitcoin::hashes::Hash;
    use bitcoin::{BlockHash, Txid};

    #[tokio::test]
    async fn add_get_block_info() {
        let config = create_test_config_with_thread_name!(None);
        let db = Database::new(&config).await.unwrap();

        let prev_block_hash = BlockHash::from_raw_hash(Hash::from_byte_array([0x1F; 32]));
        let block_hash = BlockHash::from_raw_hash(Hash::from_byte_array([0x45; 32]));
        let height = 0x45;

        assert!(db
            .get_block_info_from_hash(None, block_hash)
            .await
            .unwrap()
            .is_none());

        db.add_block_info(None, &block_hash, &prev_block_hash, height)
            .await
            .unwrap();
        let block_info = db
            .get_block_info_from_hash(None, block_hash)
            .await
            .unwrap()
            .unwrap();
        let max_height = db.get_max_height(None).await.unwrap().unwrap();
        assert_eq!(block_info.0, prev_block_hash);
        assert_eq!(block_info.1, height as u32);
        assert_eq!(max_height, height as u64);

        db.add_block_info(
            None,
            &BlockHash::from_raw_hash(Hash::from_byte_array([0x1; 32])),
            &prev_block_hash,
            height - 1,
        )
        .await
        .unwrap();
        let max_height = db.get_max_height(None).await.unwrap().unwrap();
        assert_eq!(max_height, height as u64);

        db.add_block_info(
            None,
            &BlockHash::from_raw_hash(Hash::from_byte_array([0x2; 32])),
            &prev_block_hash,
            height + 1,
        )
        .await
        .unwrap();
        let max_height = db.get_max_height(None).await.unwrap().unwrap();
        assert_ne!(max_height, height as u64);
        assert_eq!(max_height, height as u64 + 1);
    }

    #[tokio::test]
    async fn add_and_get_txids_from_block() {
        let config = create_test_config_with_thread_name!(None);
        let db = Database::new(&config).await.unwrap();
        let mut dbtx = db.begin_transaction().await.unwrap();

        assert!(db
            .add_txid_to_block(&mut dbtx, 0, &Txid::all_zeros())
            .await
            .is_err());
        let mut dbtx = db.begin_transaction().await.unwrap();

        let prev_block_hash = BlockHash::from_raw_hash(Hash::from_byte_array([0x1F; 32]));
        let block_hash = BlockHash::from_raw_hash(Hash::from_byte_array([0x45; 32]));
        let height = 0x45;
        let block_id = db
            .add_block_info(Some(&mut dbtx), &block_hash, &prev_block_hash, height)
            .await
            .unwrap();

        let txids = vec![
            Txid::from_raw_hash(Hash::from_byte_array([0x1; 32])),
            Txid::from_raw_hash(Hash::from_byte_array([0x2; 32])),
            Txid::from_raw_hash(Hash::from_byte_array([0x3; 32])),
        ];
        for txid in &txids {
            db.add_txid_to_block(&mut dbtx, block_id, txid)
                .await
                .unwrap();
        }

        let txids_from_db = db.get_block_txids(Some(&mut dbtx), block_id).await.unwrap();
        assert_eq!(txids_from_db, txids);

        assert!(db
            .get_block_txids(Some(&mut dbtx), block_id + 1)
            .await
            .unwrap()
            .is_empty());

        dbtx.commit().await.unwrap();
    }

    #[tokio::test]
    async fn insert_get_spent_utxos() {
        let config = create_test_config_with_thread_name!(None);
        let db = Database::new(&config).await.unwrap();
        let mut dbtx = db.begin_transaction().await.unwrap();

        let prev_block_hash = BlockHash::from_raw_hash(Hash::from_byte_array([0x1F; 32]));
        let block_hash = BlockHash::from_raw_hash(Hash::from_byte_array([0x45; 32]));
        let height = 0x45;
        let block_id = db
            .add_block_info(Some(&mut dbtx), &block_hash, &prev_block_hash, height)
            .await
            .unwrap();

        let spending_txid = Txid::from_raw_hash(Hash::from_byte_array([0x2; 32]));
        let txid = Txid::from_raw_hash(Hash::from_byte_array([0x1; 32]));
        let vout = 0;
        db.add_txid_to_block(&mut dbtx, block_id, &spending_txid)
            .await
            .unwrap();

        assert_eq!(
            db.get_spent_utxos_for_txid(Some(&mut dbtx), txid)
                .await
                .unwrap()
                .len(),
            0
        );

        db.insert_spent_utxo(&mut dbtx, block_id, &spending_txid, &txid, vout)
            .await
            .unwrap();

        let spent_utxos = db
            .get_spent_utxos_for_txid(Some(&mut dbtx), spending_txid)
            .await
            .unwrap();
        assert_eq!(spent_utxos.len(), 1);
        assert_eq!(spent_utxos[0].0, block_id as i64);
        assert_eq!(
            spent_utxos[0].1,
            bitcoin::OutPoint {
                txid,
                vout: vout as u32,
            }
        );

        dbtx.commit().await.unwrap();
    }
}
