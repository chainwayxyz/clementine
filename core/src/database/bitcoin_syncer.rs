use super::{
    wrapper::{BlockHashDB, TxidDB},
    Database, DatabaseTransaction,
};
use crate::{
    bitcoin_syncer::BitcoinSyncerEvent, config::protocol::ProtocolParamset, execute_query_with_tx,
};
use bitcoin::{BlockHash, OutPoint, Txid};
use clementine_errors::BridgeError;
use eyre::Context;
use std::ops::DerefMut;

impl Database {
    /// # Returns
    ///
    /// - [`u32`]: Database entry id, later to be used while referring block
    pub async fn insert_block_info(
        &self,
        tx: Option<DatabaseTransaction<'_>>,
        block_hash: &BlockHash,
        prev_block_hash: &BlockHash,
        block_height: u32,
    ) -> Result<u32, BridgeError> {
        let query = sqlx::query_scalar(
            "INSERT INTO bitcoin_syncer (blockhash, prev_blockhash, height) VALUES ($1, $2, $3) RETURNING id",
        )
        .bind(BlockHashDB(*block_hash))
        .bind(BlockHashDB(*prev_block_hash))
        .bind(i32::try_from(block_height).wrap_err(BridgeError::IntConversionError)?);

        let id: i32 = execute_query_with_tx!(self.connection, tx, query, fetch_one)?;

        u32::try_from(id)
            .wrap_err(BridgeError::IntConversionError)
            .map_err(Into::into)
    }

    /// Sets the block with given block hash as canonical if it exists in the database
    /// Returns the block id if the block was found and set as canonical, None otherwise
    pub async fn update_block_as_canonical(
        &self,
        tx: Option<DatabaseTransaction<'_>>,
        block_hash: BlockHash,
    ) -> Result<Option<u32>, BridgeError> {
        let query = sqlx::query_scalar(
            "UPDATE bitcoin_syncer SET is_canonical = true WHERE blockhash = $1 RETURNING id",
        )
        .bind(BlockHashDB(block_hash));

        let id: Option<i32> = execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

        id.map(|id| u32::try_from(id).wrap_err(BridgeError::IntConversionError))
            .transpose()
            .map_err(Into::into)
    }

    /// # Returns
    ///
    /// [`Some`] if the block exists in the database, [`None`] otherwise:
    ///
    /// - [`BlockHash`]: Previous block hash
    /// - [`u32`]: Height of the block
    pub async fn get_block_info_from_hash(
        &self,
        tx: Option<DatabaseTransaction<'_>>,
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
                let height = u32::try_from(height).wrap_err(BridgeError::IntConversionError)?;
                Ok((prev_hash.0, height))
            },
        )
        .transpose()
    }

    /// Gets block hash and height from block id (internal id used in bitcoin_syncer)
    pub async fn get_block_info_from_id(
        &self,
        tx: Option<DatabaseTransaction<'_>>,
        block_id: u32,
    ) -> Result<Option<(BlockHash, u32)>, BridgeError> {
        let query = sqlx::query_as("SELECT blockhash, height FROM bitcoin_syncer WHERE id = $1")
            .bind(i32::try_from(block_id).wrap_err(BridgeError::IntConversionError)?);

        let ret: Option<(BlockHashDB, i32)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

        ret.map(
            |(block_hash, height)| -> Result<(BlockHash, u32), BridgeError> {
                let height = u32::try_from(height).wrap_err(BridgeError::IntConversionError)?;
                Ok((block_hash.0, height))
            },
        )
        .transpose()
    }

    /// Stores the full block in bytes in the database, with its height and hash
    pub async fn upsert_full_block(
        &self,
        tx: Option<DatabaseTransaction<'_>>,
        block: &bitcoin::Block,
        block_height: u32,
    ) -> Result<(), BridgeError> {
        let block_bytes = bitcoin::consensus::serialize(block);
        let query = sqlx::query(
            "INSERT INTO bitcoin_blocks (height, block_data, block_hash) VALUES ($1, $2, $3)
             ON CONFLICT (height) DO UPDATE SET block_data = $2, block_hash = $3",
        )
        .bind(i32::try_from(block_height).wrap_err(BridgeError::IntConversionError)?)
        .bind(&block_bytes)
        .bind(BlockHashDB(block.header.block_hash()));

        execute_query_with_tx!(self.connection, tx, query, execute)?;
        Ok(())
    }

    /// Gets the full block from the database, given the block height
    pub async fn get_full_block(
        &self,
        tx: Option<DatabaseTransaction<'_>>,
        block_height: u32,
    ) -> Result<Option<bitcoin::Block>, BridgeError> {
        let query = sqlx::query_as("SELECT block_data FROM bitcoin_blocks WHERE height = $1")
            .bind(i32::try_from(block_height).wrap_err(BridgeError::IntConversionError)?);

        let block_data: Option<(Vec<u8>,)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

        match block_data {
            Some((bytes,)) => {
                let block = bitcoin::consensus::deserialize(&bytes)
                    .wrap_err(BridgeError::IntConversionError)?;
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    /// Gets the full block and its height from the database, given the block hash
    pub async fn get_full_block_from_hash(
        &self,
        tx: Option<DatabaseTransaction<'_>>,
        block_hash: BlockHash,
    ) -> Result<Option<(u32, bitcoin::Block)>, BridgeError> {
        let query =
            sqlx::query_as("SELECT height, block_data FROM bitcoin_blocks WHERE block_hash = $1")
                .bind(BlockHashDB(block_hash));

        let block_data: Option<(i32, Vec<u8>)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

        match block_data {
            Some((height_i32, bytes)) => {
                let height = u32::try_from(height_i32).wrap_err(BridgeError::IntConversionError)?;
                let block = bitcoin::consensus::deserialize(&bytes)
                    .wrap_err(BridgeError::IntConversionError)?;
                Ok(Some((height, block)))
            }
            None => Ok(None),
        }
    }

    /// Gets the maximum height of the canonical blocks in the bitcoin_syncer database
    pub async fn get_max_height(
        &self,
        tx: Option<DatabaseTransaction<'_>>,
    ) -> Result<Option<u32>, BridgeError> {
        let query =
            sqlx::query_as("SELECT height FROM bitcoin_syncer WHERE is_canonical = true ORDER BY height DESC LIMIT 1");
        let result: Option<(i32,)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

        result
            .map(|(height,)| u32::try_from(height).wrap_err(BridgeError::IntConversionError))
            .transpose()
            .map_err(Into::into)
    }

    /// Gets the block hashes that have height bigger then the given height and deletes them.
    /// Marks blocks with height bigger than the given height as non-canonical.
    ///
    /// # Parameters
    ///
    /// - `tx`: Optional transaction to use for the query.
    /// - `height`: Height to start marking blocks as such (not inclusive).
    ///
    /// # Returns
    ///
    /// - [`Vec<u32>`]: List of block ids that were marked as non-canonical in
    ///   descending order.
    pub async fn update_non_canonical_block_hashes(
        &self,
        tx: Option<DatabaseTransaction<'_>>,
        height: u32,
    ) -> Result<Vec<u32>, BridgeError> {
        let query = sqlx::query_as(
            "WITH deleted AS (
                UPDATE bitcoin_syncer
                SET is_canonical = false
                WHERE height > $1
                RETURNING id
            ) SELECT id FROM deleted ORDER BY id DESC",
        )
        .bind(i32::try_from(height).wrap_err(BridgeError::IntConversionError)?);

        let block_ids: Vec<(i32,)> = execute_query_with_tx!(self.connection, tx, query, fetch_all)?;
        block_ids
            .into_iter()
            .map(|(block_id,)| u32::try_from(block_id).wrap_err(BridgeError::IntConversionError))
            .collect::<Result<Vec<_>, eyre::Report>>()
            .map_err(Into::into)
    }

    /// Gets the block id of the canonical block at the given height
    pub async fn get_canonical_block_id_from_height(
        &self,
        tx: Option<DatabaseTransaction<'_>>,
        height: u32,
    ) -> Result<Option<u32>, BridgeError> {
        let query = sqlx::query_as(
            "SELECT id FROM bitcoin_syncer WHERE height = $1 AND is_canonical = true",
        )
        .bind(i32::try_from(height).wrap_err(BridgeError::IntConversionError)?);

        let block_id: Option<(i32,)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

        block_id
            .map(|(block_id,)| u32::try_from(block_id).wrap_err(BridgeError::IntConversionError))
            .transpose()
            .map_err(Into::into)
    }

    /// Saves the txid with the id of the block that contains it to the database
    pub async fn insert_txid_to_block(
        &self,
        tx: DatabaseTransaction<'_>,
        block_id: u32,
        txid: &bitcoin::Txid,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query("INSERT INTO bitcoin_syncer_txs (block_id, txid) VALUES ($1, $2)")
            .bind(i32::try_from(block_id).wrap_err(BridgeError::IntConversionError)?)
            .bind(super::wrapper::TxidDB(*txid));

        execute_query_with_tx!(self.connection, Some(tx), query, execute)?;

        Ok(())
    }

    /// Gets all the txids that are contained in the block with the given id
    #[cfg(test)]
    pub async fn get_block_txids(
        &self,
        tx: Option<DatabaseTransaction<'_>>,
        block_id: u32,
    ) -> Result<Vec<Txid>, BridgeError> {
        let query = sqlx::query_as("SELECT txid FROM bitcoin_syncer_txs WHERE block_id = $1")
            .bind(i32::try_from(block_id).wrap_err(BridgeError::IntConversionError)?);

        let txids: Vec<(TxidDB,)> = execute_query_with_tx!(self.connection, tx, query, fetch_all)?;

        Ok(txids.into_iter().map(|(txid,)| txid.0).collect())
    }

    /// Gets the block height for txids that exist in canonical blocks.
    /// Returns a mapping of txid -> block_height for those that exist.
    pub async fn get_canonical_block_heights_for_txids(
        &self,
        tx: Option<DatabaseTransaction<'_>>,
        txids: &[Txid],
    ) -> Result<Vec<(Txid, u32)>, BridgeError> {
        if txids.is_empty() {
            return Ok(Vec::new());
        }

        // Convert txids to TxidDB for array binding
        let txid_params: Vec<TxidDB> = txids.iter().map(|t| TxidDB(*t)).collect();

        // Use TxidDB for result decoding to be consistent with the rest of the codebase
        let query = sqlx::query_as::<_, (TxidDB, i32)>(
            "SELECT bst.txid, bs.height
             FROM bitcoin_syncer_txs bst
             INNER JOIN bitcoin_syncer bs ON bst.block_id = bs.id
             WHERE bst.txid = ANY($1) AND bs.is_canonical = true",
        )
        .bind(&txid_params);

        let results: Vec<(TxidDB, i32)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_all)?;

        results
            .into_iter()
            .map(|(txid, height)| {
                let height =
                    u32::try_from(height).wrap_err("Failed to convert block height to u32")?;
                Ok((txid.0, height))
            })
            .collect()
    }

    /// Checks if a txid exists in a canonical block.
    /// Returns Some(block_height) if found, None otherwise.
    pub async fn get_canonical_block_height_for_txid(
        &self,
        tx: Option<DatabaseTransaction<'_>>,
        txid: Txid,
    ) -> Result<Option<u32>, BridgeError> {
        let query = sqlx::query_scalar::<_, i32>(
            "SELECT bs.height
             FROM bitcoin_syncer_txs bst
             INNER JOIN bitcoin_syncer bs ON bst.block_id = bs.id
             WHERE bst.txid = $1 AND bs.is_canonical = true",
        )
        .bind(TxidDB(txid));

        let result: Option<i32> =
            execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

        result
            .map(|height| u32::try_from(height).wrap_err("Failed to convert block height to u32"))
            .transpose()
            .map_err(Into::into)
    }

    /// Inserts a spent utxo into the database, with the block id that contains it, the spending txid and the vout
    pub async fn insert_spent_utxo(
        &self,
        tx: DatabaseTransaction<'_>,
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

    /// For a given outpoint, gets the block height of the canonical block that spent it.
    /// Returns None if the outpoint is not spent.
    pub async fn get_block_height_of_spending_txid(
        &self,
        tx: Option<DatabaseTransaction<'_>>,
        outpoint: OutPoint,
    ) -> Result<Option<u32>, BridgeError> {
        let query = sqlx::query_scalar::<_, i32>(
            "SELECT bs.height FROM bitcoin_syncer_spent_utxos bspu
                INNER JOIN bitcoin_syncer bs ON bspu.block_id = bs.id
                WHERE bspu.txid = $1 AND bspu.vout = $2 AND bs.is_canonical = true",
        )
        .bind(super::wrapper::TxidDB(outpoint.txid))
        .bind(outpoint.vout as i64);

        let result: Option<i32> =
            execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

        result
            .map(|height| u32::try_from(height).wrap_err(BridgeError::IntConversionError))
            .transpose()
            .map_err(Into::into)
    }

    /// Checks if the utxo is spent, if so checks if the spending tx is finalized
    /// Returns true if the utxo is spent and the spending tx is finalized, false otherwise
    pub async fn check_if_utxo_spending_tx_is_finalized(
        &self,
        tx: Option<DatabaseTransaction<'_>>,
        outpoint: OutPoint,
        current_chain_height: u32,
        protocol_paramset: &'static ProtocolParamset,
    ) -> Result<bool, BridgeError> {
        let spending_tx_height = self.get_block_height_of_spending_txid(tx, outpoint).await?;
        match spending_tx_height {
            Some(spending_tx_height) => {
                Ok(protocol_paramset.is_block_finalized(spending_tx_height, current_chain_height))
            }
            None => Ok(false),
        }
    }

    /// Gets all the spent utxos for a given txid
    pub async fn get_spent_utxos_for_txid(
        &self,
        tx: Option<DatabaseTransaction<'_>>,
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
                    let vout = u32::try_from(vout).wrap_err(BridgeError::IntConversionError)?;
                    Ok((block_id, OutPoint { txid: txid.0, vout }))
                },
            )
            .collect::<Result<Vec<_>, BridgeError>>()
    }

    /// Adds a bitcoin syncer event to the database. These events can currently be new block or reorged block.
    pub async fn insert_event(
        &self,
        tx: Option<DatabaseTransaction<'_>>,
        event_type: BitcoinSyncerEvent,
    ) -> Result<(), BridgeError> {
        let query = match event_type {
            BitcoinSyncerEvent::NewBlock(block_id) => sqlx::query(
                "INSERT INTO bitcoin_syncer_events (block_id, event_type) VALUES ($1, 'new_block'::bitcoin_syncer_event_type)",
            )
            .bind(i32::try_from(block_id).wrap_err(BridgeError::IntConversionError)?),
            BitcoinSyncerEvent::ReorgedBlock(block_id) => sqlx::query(
                "INSERT INTO bitcoin_syncer_events (block_id, event_type) VALUES ($1, 'reorged_block'::bitcoin_syncer_event_type)",
            )
            .bind(i32::try_from(block_id).wrap_err(BridgeError::IntConversionError)?),
        };
        execute_query_with_tx!(self.connection, tx, query, execute)?;
        Ok(())
    }

    /// Returns the last processed Bitcoin Syncer event's block height for given consumer.
    /// If the last processed event is missing, i.e. there are no processed events for the consumer, returns `None`.
    pub async fn get_last_processed_event_block_height(
        &self,
        tx: Option<DatabaseTransaction<'_>>,
        consumer_handle: &str,
    ) -> Result<Option<u32>, BridgeError> {
        let query = sqlx::query_scalar::<_, i32>(
            r#"SELECT bs.height
             FROM bitcoin_syncer_event_handlers bseh
             INNER JOIN bitcoin_syncer_events bse ON bseh.last_processed_event_id = bse.id
             INNER JOIN bitcoin_syncer bs ON bse.block_id = bs.id
             WHERE bseh.consumer_handle = $1"#,
        )
        .bind(consumer_handle);

        let result: Option<i32> =
            execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

        result
            .map(|h| {
                u32::try_from(h)
                    .wrap_err(BridgeError::IntConversionError)
                    .map_err(BridgeError::from)
            })
            .transpose()
    }

    /// Gets the last processed event id for a given consumer
    pub async fn get_last_processed_event_id(
        &self,
        tx: DatabaseTransaction<'_>,
        consumer_handle: &str,
    ) -> Result<i32, BridgeError> {
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

        Ok(last_processed_event_id)
    }

    /// Returns the maximum block height of the blocks that have been processed by the given consumer.
    /// If the last processed event is missing, i.e. there are no processed events for the consumer, returns `None`.
    pub async fn get_max_processed_block_height(
        &self,
        tx: Option<DatabaseTransaction<'_>>,
        consumer_handle: &str,
    ) -> Result<Option<u32>, BridgeError> {
        let query = sqlx::query_scalar::<_, Option<i32>>(
            r#"SELECT MAX(bs.height)
             FROM bitcoin_syncer_events bse
             INNER JOIN bitcoin_syncer bs ON bse.block_id = bs.id
             WHERE bse.id <= (
                 SELECT last_processed_event_id
                 FROM bitcoin_syncer_event_handlers
                 WHERE consumer_handle = $1
             )"#,
        )
        .bind(consumer_handle);

        let result: Option<i32> = execute_query_with_tx!(self.connection, tx, query, fetch_one)?;

        result
            .map(|h| {
                u32::try_from(h)
                    .wrap_err(BridgeError::IntConversionError)
                    .map_err(BridgeError::from)
            })
            .transpose()
    }

    /// Returns the next finalized block height that should be processed by the given consumer.
    /// If there are no processed events, returns the paramset start height.
    /// Next height is the max height of the processed block - finality depth + 1.
    pub async fn get_next_finalized_block_height_for_consumer(
        &self,
        tx: Option<DatabaseTransaction<'_>>,
        consumer_handle: &str,
        paramset: &'static ProtocolParamset,
    ) -> Result<u32, BridgeError> {
        let max_processed_block_height = self
            .get_max_processed_block_height(tx, consumer_handle)
            .await?;

        let max_processed_finalized_block_height = match max_processed_block_height {
            Some(max_processed_block_height) => {
                max_processed_block_height.checked_sub(paramset.finality_depth - 1)
            }
            None => None,
        };

        let next_height = max_processed_finalized_block_height
            .map(|h| h + 1)
            .unwrap_or(paramset.start_height);

        Ok(std::cmp::max(next_height, paramset.start_height))
    }

    /// Fetches the next bitcoin syncer event for a given consumer
    /// This function is used to fetch the next event that hasn't been processed yet
    /// It will return the event which includes the event type and the block id
    /// The last updated event id is also updated to the id that is returned
    /// If there are no more events to fetch, None is returned
    pub async fn fetch_next_bitcoin_syncer_evt(
        &self,
        tx: DatabaseTransaction<'_>,
        consumer_handle: &str,
    ) -> Result<Option<BitcoinSyncerEvent>, BridgeError> {
        // Get the last processed event ID for this consumer
        let last_processed_event_id = self
            .get_last_processed_event_id(tx, consumer_handle)
            .await?;

        // Retrieve the next event that hasn't been processed yet
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
        let event_id = event.0;
        let event_type: BitcoinSyncerEvent = (event.2, event.1).try_into()?;

        // Update last_processed_event_id for this consumer
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
    use bitcoin::{BlockHash, CompactTarget};

    async fn setup_test_db() -> Database {
        let config = create_test_config_with_thread_name().await;
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
            .insert_block_info(Some(&mut dbtx), &block_hash, &prev_block_hash, height)
            .await
            .unwrap();

        // Add new block event
        db.insert_event(Some(&mut dbtx), BitcoinSyncerEvent::NewBlock(block_id))
            .await
            .unwrap();

        // Test event consumption
        let consumer_handle = "test_consumer";
        let event = db
            .fetch_next_bitcoin_syncer_evt(&mut dbtx, consumer_handle)
            .await
            .unwrap();

        assert!(matches!(event, Some(BitcoinSyncerEvent::NewBlock(id)) if id == block_id));

        // Test that the same event is not returned twice
        let event = db
            .fetch_next_bitcoin_syncer_evt(&mut dbtx, consumer_handle)
            .await
            .unwrap();
        assert!(event.is_none());

        // Add reorg event
        db.insert_event(Some(&mut dbtx), BitcoinSyncerEvent::ReorgedBlock(block_id))
            .await
            .unwrap();

        // Test that new event is received
        let event = db
            .fetch_next_bitcoin_syncer_evt(&mut dbtx, consumer_handle)
            .await
            .unwrap();
        assert!(matches!(event, Some(BitcoinSyncerEvent::ReorgedBlock(id)) if id == block_id));

        dbtx.commit().await.unwrap();
    }

    #[tokio::test]
    async fn test_store_and_get_block() {
        let db = setup_test_db().await;
        let block_height = 123u32;

        // Create a dummy block
        let dummy_header = bitcoin::block::Header {
            version: bitcoin::block::Version::TWO,
            prev_blockhash: BlockHash::from_raw_hash(Hash::from_byte_array([0x42; 32])),
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 1_000_000,
            bits: CompactTarget::from_consensus(0),
            nonce: 12345,
        };

        let dummy_txs = vec![bitcoin::Transaction {
            version: bitcoin::blockdata::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        }];

        let dummy_block = bitcoin::Block {
            header: dummy_header,
            txdata: dummy_txs.clone(),
        };

        let dummy_block_hash = dummy_block.block_hash();

        // Store the block
        db.upsert_full_block(None, &dummy_block, block_height)
            .await
            .unwrap();

        // Retrieve the block
        let retrieved_block = db
            .get_full_block(None, block_height)
            .await
            .unwrap()
            .unwrap();

        // Verify block fields match
        assert_eq!(retrieved_block, dummy_block);

        // Retrieve the block
        let retrieved_block_from_hash = db
            .get_full_block_from_hash(None, dummy_block_hash)
            .await
            .unwrap()
            .unwrap()
            .1;

        // Verify block fields match
        assert_eq!(retrieved_block_from_hash, dummy_block);

        // Non-existent block should return None
        assert!(db.get_full_block(None, 999).await.unwrap().is_none());

        // Overwrite the block
        let updated_dummy_header = bitcoin::block::Header {
            version: bitcoin::block::Version::ONE, // Changed version
            ..dummy_header
        };
        let updated_dummy_block = bitcoin::Block {
            header: updated_dummy_header,
            txdata: dummy_txs.clone(),
        };

        let updated_dummy_block_hash = updated_dummy_block.block_hash();

        db.upsert_full_block(None, &updated_dummy_block, block_height)
            .await
            .unwrap();

        // Verify the update worked
        let retrieved_updated_block = db
            .get_full_block(None, block_height)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated_dummy_block, retrieved_updated_block);

        let retrieved_updated_block_from_hash = db
            .get_full_block_from_hash(None, updated_dummy_block_hash)
            .await
            .unwrap()
            .unwrap()
            .1;
        assert_eq!(updated_dummy_block, retrieved_updated_block_from_hash);
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
            .insert_block_info(Some(&mut dbtx), &block_hash, &prev_block_hash, height)
            .await
            .unwrap();

        // Add events
        db.insert_event(Some(&mut dbtx), BitcoinSyncerEvent::NewBlock(block_id))
            .await
            .unwrap();
        db.insert_event(Some(&mut dbtx), BitcoinSyncerEvent::ReorgedBlock(block_id))
            .await
            .unwrap();

        // Test with multiple consumers
        let consumer1 = "consumer1";
        let consumer2 = "consumer2";

        // First consumer gets both events in order
        let event1 = db
            .fetch_next_bitcoin_syncer_evt(&mut dbtx, consumer1)
            .await
            .unwrap();
        assert!(matches!(event1, Some(BitcoinSyncerEvent::NewBlock(id)) if id == block_id));

        let event2 = db
            .fetch_next_bitcoin_syncer_evt(&mut dbtx, consumer1)
            .await
            .unwrap();
        assert!(matches!(event2, Some(BitcoinSyncerEvent::ReorgedBlock(id)) if id == block_id));

        // Second consumer also gets both events independently
        let event1 = db
            .fetch_next_bitcoin_syncer_evt(&mut dbtx, consumer2)
            .await
            .unwrap();
        assert!(matches!(event1, Some(BitcoinSyncerEvent::NewBlock(id)) if id == block_id));

        let event2 = db
            .fetch_next_bitcoin_syncer_evt(&mut dbtx, consumer2)
            .await
            .unwrap();
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

        // Save some initial blocks.
        let mut block_ids = Vec::new();
        for height in heights {
            let block_hash = BlockHash::from_raw_hash(Hash::from_byte_array([height as u8; 32]));
            let block_id = db
                .insert_block_info(Some(&mut dbtx), &block_hash, &last_hash, height)
                .await
                .unwrap();
            block_ids.push(block_id);
            last_hash = block_hash;
        }

        // Mark blocks above height 2 as non-canonical.
        let non_canonical_blocks = db
            .update_non_canonical_block_hashes(Some(&mut dbtx), 2)
            .await
            .unwrap();
        assert_eq!(non_canonical_blocks.len(), 3);
        assert_eq!(non_canonical_blocks, vec![5, 4, 3]);

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
        let config = create_test_config_with_thread_name().await;
        let db = Database::new(&config).await.unwrap();

        let prev_block_hash = BlockHash::from_raw_hash(Hash::from_byte_array([0x1F; 32]));
        let block_hash = BlockHash::from_raw_hash(Hash::from_byte_array([0x45; 32]));
        let height = 0x45;

        assert!(db
            .get_block_info_from_hash(None, block_hash)
            .await
            .unwrap()
            .is_none());

        db.insert_block_info(None, &block_hash, &prev_block_hash, height)
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

        db.insert_block_info(
            None,
            &BlockHash::from_raw_hash(Hash::from_byte_array([0x1; 32])),
            &prev_block_hash,
            height - 1,
        )
        .await
        .unwrap();
        let max_height = db.get_max_height(None).await.unwrap().unwrap();
        assert_eq!(max_height, height);

        db.insert_block_info(
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
        let config = create_test_config_with_thread_name().await;
        let db = Database::new(&config).await.unwrap();
        let mut dbtx = db.begin_transaction().await.unwrap();

        assert!(db
            .insert_txid_to_block(&mut dbtx, 0, &Txid::all_zeros())
            .await
            .is_err());
        let mut dbtx = db.begin_transaction().await.unwrap();

        let prev_block_hash = BlockHash::from_raw_hash(Hash::from_byte_array([0x1F; 32]));
        let block_hash = BlockHash::from_raw_hash(Hash::from_byte_array([0x45; 32]));
        let height = 0x45;
        let block_id = db
            .insert_block_info(Some(&mut dbtx), &block_hash, &prev_block_hash, height)
            .await
            .unwrap();

        let txids = vec![
            Txid::from_raw_hash(Hash::from_byte_array([0x1; 32])),
            Txid::from_raw_hash(Hash::from_byte_array([0x2; 32])),
            Txid::from_raw_hash(Hash::from_byte_array([0x3; 32])),
        ];
        for txid in &txids {
            db.insert_txid_to_block(&mut dbtx, block_id, txid)
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
        let config = create_test_config_with_thread_name().await;
        let db = Database::new(&config).await.unwrap();
        let mut dbtx = db.begin_transaction().await.unwrap();

        let prev_block_hash = BlockHash::from_raw_hash(Hash::from_byte_array([0x1F; 32]));
        let block_hash = BlockHash::from_raw_hash(Hash::from_byte_array([0x45; 32]));
        let height = 0x45;
        let block_id = db
            .insert_block_info(Some(&mut dbtx), &block_hash, &prev_block_hash, height)
            .await
            .unwrap();

        let spending_txid = Txid::from_raw_hash(Hash::from_byte_array([0x2; 32]));
        let txid = Txid::from_raw_hash(Hash::from_byte_array([0x1; 32]));
        let vout = 0;
        db.insert_txid_to_block(&mut dbtx, block_id, &spending_txid)
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
