use super::{wrapper::BlockHashDB, Database, DatabaseTransaction};
use crate::{errors::BridgeError, execute_query_with_tx};
use bitcoin::BlockHash;
use std::{ops::DerefMut, str::FromStr};

impl Database {
    pub async fn set_chain_head(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        block_hash: &BlockHash,
        prev_block_hash: &BlockHash,
        block_height: i64,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "INSERT INTO bitcoin_syncer (blockhash, prev_blockhash, height) VALUES ($1, $2, $3)",
        )
        .bind(BlockHashDB(block_hash.clone()))
        .bind(BlockHashDB(prev_block_hash.clone()))
        .bind(block_height);

        execute_query_with_tx!(self.connection, tx, query, execute)?;

        Ok(())
    }

    pub async fn get_max_height(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
    ) -> Result<Option<u64>, BridgeError> {
        let query =
            sqlx::query_as("SELECT height FROM bitcoin_syncer ORDER BY height DESC LIMIT 1");
        let result: Option<(i64,)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;
        Ok(result.map(|(height,)| height as u64))
    }

    /// Gets the height from the block hash.
    pub async fn get_height_from_block_hash(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        block_hash: BlockHash,
    ) -> Result<Option<u64>, BridgeError> {
        let query = sqlx::query_as("SELECT height FROM tx_sender_block_info WHERE block_hash = $1")
            .bind(block_hash.to_string());

        let height: Option<(i64,)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;
        Ok(height.map(|(h,)| h as u64))
    }

    /// Gets the block hashes that have height bigger then the given height and deletes them.
    pub async fn delete_chain_head_from_height(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        height: u64,
    ) -> Result<Vec<BlockHash>, BridgeError> {
        let query = sqlx::query_as(
            "WITH deleted AS (
                DELETE FROM tx_sender_block_info 
                WHERE height > $1 
                RETURNING block_hash
            ) SELECT block_hash FROM deleted",
        )
        .bind(height as i64);

        let block_hashes: Vec<(String,)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_all)?;
        Ok(block_hashes
            .into_iter()
            .map(|(hash,)| BlockHash::from_str(&hash))
            .collect::<Result<Vec<_>, _>>()?)
    }

    pub async fn insert_tx(
        &self,
        tx: DatabaseTransaction<'_, '_>,
        block_hash: &bitcoin::BlockHash,
        txid: &bitcoin::Txid,
    ) -> Result<(), BridgeError> {
        sqlx::query("INSERT INTO bitcoin_syncer_txs (blockhash, txid) VALUES ($1, $2)")
            .bind(super::wrapper::BlockHashDB(block_hash.clone()))
            .bind(super::wrapper::TxidDB(txid.clone()))
            .execute(tx.deref_mut())
            .await?;
        Ok(())
    }

    pub async fn select_one_tx(
        &self,
        tx: DatabaseTransaction<'_, '_>,
        txid: &bitcoin::Txid,
    ) -> Result<Option<bitcoin::BlockHash>, BridgeError> {
        let ret: Option<(super::wrapper::BlockHashDB,)> =
            sqlx::query_as("SELECT blockhash FROM bitcoin_syncer_txs WHERE txid = $1")
                .bind(super::wrapper::TxidDB(txid.clone()))
                .fetch_optional(tx.deref_mut())
                .await?;
        Ok(ret.map(|ret| ret.0 .0))
    }

    pub async fn select_all_txs(
        &self,
        tx: DatabaseTransaction<'_, '_>,
        block_hash: &bitcoin::BlockHash,
    ) -> Result<Vec<bitcoin::Txid>, BridgeError> {
        let ret: Vec<(super::wrapper::TxidDB,)> =
            sqlx::query_as("SELECT txid FROM bitcoin_syncer_txs WHERE blockhash = $1")
                .bind(super::wrapper::BlockHashDB(block_hash.clone()))
                .fetch_all(tx.deref_mut())
                .await?;
        Ok(ret.into_iter().map(|ret| ret.0 .0).collect())
    }

    pub async fn insert_utxo(
        &self,
        tx: DatabaseTransaction<'_, '_>,
        spending_txid: &bitcoin::Txid,
        txid: &bitcoin::Txid,
        vout: i64,
    ) -> Result<(), BridgeError> {
        sqlx::query(
            "INSERT INTO bitcoin_syncer_utxos (spending_txid, txid, vout) VALUES ($1, $2, $3)",
        )
        .bind(super::wrapper::TxidDB(spending_txid.clone()))
        .bind(super::wrapper::TxidDB(txid.clone()))
        .bind(vout)
        .execute(tx.deref_mut())
        .await?;
        Ok(())
    }
}
