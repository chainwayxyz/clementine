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
        block_height: u32,
    ) -> Result<u32, BridgeError> {
        let query = sqlx::query_scalar(
            "INSERT INTO bitcoin_syncer (blockhash, prev_blockhash, height) VALUES ($1, $2, $3) RETURNING id",
        )
        .bind(BlockHashDB(*block_hash))
        .bind(BlockHashDB(*prev_block_hash))
        .bind(i32::try_from(block_height).map_err(|e| BridgeError::ConversionError(e.to_string()))?);

        let id: i32 = execute_query_with_tx!(self.connection, tx, query, fetch_one)?;

        u32::try_from(id).map_err(|e| BridgeError::ConversionError(e.to_string()))
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

        let ret: Option<(BlockHashDB, i32)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

        ret.map(
            |(prev_hash, height)| -> Result<(BlockHash, u32), BridgeError> {
                let height = u32::try_from(height)
                    .map_err(|e| BridgeError::ConversionError(e.to_string()))?;
                Ok((prev_hash.0, height))
            },
        )
        .transpose()
    }

    pub async fn get_block_info_from_id(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        block_id: u32,
    ) -> Result<Option<(BlockHash, u32)>, BridgeError> {
        let query = sqlx::query_as(
            "SELECT blockhash, height FROM bitcoin_syncer WHERE id = $1 AND is_canonical = true",
        )
        .bind(i32::try_from(block_id).map_err(|e| BridgeError::ConversionError(e.to_string()))?);

        let ret: Option<(BlockHashDB, i32)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

        ret.map(
            |(block_hash, height)| -> Result<(BlockHash, u32), BridgeError> {
                let height = u32::try_from(height)
                    .map_err(|e| BridgeError::ConversionError(e.to_string()))?;
                Ok((block_hash.0, height))
            },
        )
        .transpose()
    }

    pub async fn get_max_height(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
    ) -> Result<Option<u32>, BridgeError> {
        let query =
            sqlx::query_as("SELECT height FROM bitcoin_syncer WHERE is_canonical = true ORDER BY height DESC LIMIT 1");
        let result: Option<(i32,)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

        result
            .map(|(height,)| {
                u32::try_from(height).map_err(|e| BridgeError::ConversionError(e.to_string()))
            })
            .transpose()
    }

    /// Gets the block hashes that have height bigger then the given height and deletes them.
    pub async fn set_non_canonical_block_hashes(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        height: u32,
    ) -> Result<Vec<u32>, BridgeError> {
        let query = sqlx::query_as(
            "WITH deleted AS (
                UPDATE bitcoin_syncer
                SET is_canonical = false
                WHERE height > $1
                RETURNING id
            ) SELECT id FROM deleted",
        )
        .bind(i32::try_from(height).map_err(|e| BridgeError::ConversionError(e.to_string()))?);

        let block_ids: Vec<(i32,)> = execute_query_with_tx!(self.connection, tx, query, fetch_all)?;
        block_ids
            .into_iter()
            .map(|(block_id,)| {
                u32::try_from(block_id).map_err(|e| BridgeError::ConversionError(e.to_string()))
            })
            .collect::<Result<Vec<_>, BridgeError>>()
    }

    pub async fn add_txid_to_block(
        &self,
        tx: DatabaseTransaction<'_, '_>,
        block_id: u32,
        txid: &bitcoin::Txid,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query("INSERT INTO bitcoin_syncer_txs (block_id, txid) VALUES ($1, $2)")
            .bind(i32::try_from(block_id).map_err(|e| BridgeError::ConversionError(e.to_string()))?)
            .bind(super::wrapper::TxidDB(*txid));

        execute_query_with_tx!(self.connection, Some(tx), query, execute)?;

        Ok(())
    }
    pub async fn get_block_txids(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        block_id: u32,
    ) -> Result<Vec<Txid>, BridgeError> {
        let query = sqlx::query_as("SELECT txid FROM bitcoin_syncer_txs WHERE block_id = $1").bind(
            i32::try_from(block_id).map_err(|e| BridgeError::ConversionError(e.to_string()))?,
        );

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

        spent_utxos
            .into_iter()
            .map(
                |(block_id, txid, vout)| -> Result<(i64, OutPoint), BridgeError> {
                    let vout = u32::try_from(vout)
                        .map_err(|e| BridgeError::ConversionError(e.to_string()))?;
                    Ok((block_id, OutPoint { txid: txid.0, vout }))
                },
            )
            .collect::<Result<Vec<_>, BridgeError>>()
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
            .bind(i32::try_from(block_id).map_err(|e| BridgeError::ConversionError(e.to_string()))?),
            BitcoinSyncerEvent::ReorgedBlock(block_id) => sqlx::query(
                "INSERT INTO bitcoin_syncer_events (block_id, event_type) VALUES ($1, 'reorged_block'::bitcoin_syncer_event_type)",
            )
            .bind(i32::try_from(block_id).map_err(|e| BridgeError::ConversionError(e.to_string()))?),
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
            "new_block" => BitcoinSyncerEvent::NewBlock(
                u32::try_from(event.1).map_err(|e| BridgeError::ConversionError(e.to_string()))?,
            ),
            "reorged_block" => BitcoinSyncerEvent::ReorgedBlock(
                u32::try_from(event.1).map_err(|e| BridgeError::ConversionError(e.to_string()))?,
            ),
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
    use super::*;
    use crate::database::Database;
    use crate::test::common::*;

    use bitcoin::hashes::Hash;
    use bitcoin::BlockHash;

    async fn setup_test_db() -> Database {
        let config = create_test_config_with_thread_name(None).await;
        Database::new(&config).await.unwrap()
    }

    #[tokio::test]
    async fn test_event_handling() {
        let db = setup_test_db().await;
        let mut dbtx = db.begin_transaction().await.unwrap();

        // Create a test block
        let prev_block_hash = BlockHash::from_raw_hash(Hash::from_byte_array([0x1F; 32]));
        let block_hash = BlockHash::from_raw_hash(Hash::from_byte_array([0x45; 32]));
        let height = 0x45;

        let block_id = db
            .add_block_info(Some(&mut dbtx), &block_hash, &prev_block_hash, height)
            .await
            .unwrap();

        // Add new block event
        db.add_event(Some(&mut dbtx), BitcoinSyncerEvent::NewBlock(block_id))
            .await
            .unwrap();

        // Test event consumption
        let consumer_handle = "test_consumer";
        let event = db
            .get_event_and_update(&mut dbtx, consumer_handle)
            .await
            .unwrap();

        assert!(matches!(event, Some(BitcoinSyncerEvent::NewBlock(id)) if id == block_id));

        // Test that the same event is not returned twice
        let event = db
            .get_event_and_update(&mut dbtx, consumer_handle)
            .await
            .unwrap();
        assert!(event.is_none());

        // Add reorg event
        db.add_event(Some(&mut dbtx), BitcoinSyncerEvent::ReorgedBlock(block_id))
            .await
            .unwrap();

        // Test that new event is received
        let event = db
            .get_event_and_update(&mut dbtx, consumer_handle)
            .await
            .unwrap();
        assert!(matches!(event, Some(BitcoinSyncerEvent::ReorgedBlock(id)) if id == block_id));

        dbtx.commit().await.unwrap();
    }

    #[tokio::test]
    async fn test_multiple_event_consumers() {
        let db = setup_test_db().await;
        let mut dbtx = db.begin_transaction().await.unwrap();

        // Create a test block
        let prev_block_hash = BlockHash::from_raw_hash(Hash::from_byte_array([0x1F; 32]));
        let block_hash = BlockHash::from_raw_hash(Hash::from_byte_array([0x45; 32]));
        let height = 0x45;

        let block_id = db
            .add_block_info(Some(&mut dbtx), &block_hash, &prev_block_hash, height)
            .await
            .unwrap();

        // Add events
        db.add_event(Some(&mut dbtx), BitcoinSyncerEvent::NewBlock(block_id))
            .await
            .unwrap();
        db.add_event(Some(&mut dbtx), BitcoinSyncerEvent::ReorgedBlock(block_id))
            .await
            .unwrap();

        // Test with multiple consumers
        let consumer1 = "consumer1";
        let consumer2 = "consumer2";

        // First consumer gets both events in order
        let event1 = db.get_event_and_update(&mut dbtx, consumer1).await.unwrap();
        assert!(matches!(event1, Some(BitcoinSyncerEvent::NewBlock(id)) if id == block_id));

        let event2 = db.get_event_and_update(&mut dbtx, consumer1).await.unwrap();
        assert!(matches!(event2, Some(BitcoinSyncerEvent::ReorgedBlock(id)) if id == block_id));

        // Second consumer also gets both events independently
        let event1 = db.get_event_and_update(&mut dbtx, consumer2).await.unwrap();
        assert!(matches!(event1, Some(BitcoinSyncerEvent::NewBlock(id)) if id == block_id));

        let event2 = db.get_event_and_update(&mut dbtx, consumer2).await.unwrap();
        assert!(matches!(event2, Some(BitcoinSyncerEvent::ReorgedBlock(id)) if id == block_id));

        dbtx.commit().await.unwrap();
    }

    #[tokio::test]
    async fn test_non_canonical_blocks() {
        let db = setup_test_db().await;
        let mut dbtx = db.begin_transaction().await.unwrap();

        // Create a chain of blocks
        let prev_block_hash = BlockHash::from_raw_hash(Hash::from_byte_array([0x1F; 32]));
        let heights = [1, 2, 3, 4, 5];
        let mut last_hash = prev_block_hash;

        let mut block_ids = Vec::new();
        for height in heights {
            let block_hash = BlockHash::from_raw_hash(Hash::from_byte_array([height as u8; 32]));
            let block_id = db
                .add_block_info(Some(&mut dbtx), &block_hash, &last_hash, height)
                .await
                .unwrap();
            block_ids.push(block_id);
            last_hash = block_hash;
        }

        // Mark blocks above height 2 as non-canonical
        let non_canonical_blocks = db
            .set_non_canonical_block_hashes(Some(&mut dbtx), 2)
            .await
            .unwrap();
        assert_eq!(non_canonical_blocks.len(), 3); // blocks at height 3, 4, and 5

        // Verify blocks above height 2 are not returned
        for height in heights {
            let block_hash = BlockHash::from_raw_hash(Hash::from_byte_array([height as u8; 32]));
            let block_info = db
                .get_block_info_from_hash(Some(&mut dbtx), block_hash)
                .await
                .unwrap();

            if height <= 2 {
                assert!(block_info.is_some());
            } else {
                assert!(block_info.is_none());
            }
        }

        // Verify max height is now 2
        let max_height = db.get_max_height(Some(&mut dbtx)).await.unwrap().unwrap();
        assert_eq!(max_height, 2);

        dbtx.commit().await.unwrap();
    }

    #[tokio::test]
    async fn add_get_block_info() {
        let config = create_test_config_with_thread_name(None).await;
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
        assert_eq!(block_info.1, height);
        assert_eq!(max_height, height);

        db.add_block_info(
            None,
            &BlockHash::from_raw_hash(Hash::from_byte_array([0x1; 32])),
            &prev_block_hash,
            height - 1,
        )
        .await
        .unwrap();
        let max_height = db.get_max_height(None).await.unwrap().unwrap();
        assert_eq!(max_height, height);

        db.add_block_info(
            None,
            &BlockHash::from_raw_hash(Hash::from_byte_array([0x2; 32])),
            &prev_block_hash,
            height + 1,
        )
        .await
        .unwrap();
        let max_height = db.get_max_height(None).await.unwrap().unwrap();
        assert_ne!(max_height, height);
        assert_eq!(max_height, height + 1);
    }

    #[tokio::test]
    async fn add_and_get_txids_from_block() {
        let config = create_test_config_with_thread_name(None).await;
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
        let config = create_test_config_with_thread_name(None).await;
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
