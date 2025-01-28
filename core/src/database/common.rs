//! # Common Database Operations
//!
//! Common database operations for both operator and verifier. This module
//! directly talks with PostgreSQL. It is expected that PostgreSQL is properly
//! installed and configured.

use super::wrapper::{BlockHashDB, BlockHeaderDB};
use super::wrapper::{OutPointDB, SignatureDB, SignaturesDB, TxOutDB, TxidDB, UtxoDB};
use super::Database;
use crate::errors::BridgeError;
use crate::UTXO;
use bitcoin::secp256k1::schnorr;
use bitcoin::{
    block::{self, Header, Version},
    hashes::Hash,
    BlockHash, CompactTarget, TxMerkleNode,
};
use bitcoin::{OutPoint, ScriptBuf, Txid, XOnlyPublicKey};
use bitvm::signatures::winternitz;
use bitvm::signatures::winternitz::PublicKey as WinternitzPublicKey;
use risc0_zkvm::Receipt;
use sqlx::{Postgres, QueryBuilder};

pub type RootHash = [u8; 32];
pub type PublicInputWots = Vec<[u8; 20]>;
pub type AssertTxAddrs = Vec<ScriptBuf>;

pub type BitvmSetup = (AssertTxAddrs, RootHash, PublicInputWots);

impl Database {
    #[tracing::instrument(skip(self, slash_or_take_sigs), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn save_slash_or_take_sigs(
        &self,
        deposit_outpoint: OutPoint,
        slash_or_take_sigs: impl IntoIterator<Item = schnorr::Signature>,
    ) -> Result<(), BridgeError> {
        QueryBuilder::new(
            "UPDATE deposit_kickoff_utxos
             SET slash_or_take_sig = batch.sig
             FROM (",
        )
        .push_values(
            slash_or_take_sigs.into_iter().enumerate(),
            |mut builder, (i, slash_or_take_sig)| {
                builder
                    .push_bind(i as i32)
                    .push_bind(SignatureDB(slash_or_take_sig));
            },
        )
        .push(
            ") AS batch (operator_idx, sig)
             WHERE deposit_kickoff_utxos.deposit_outpoint = ",
        )
        .push_bind(OutPointDB(deposit_outpoint))
        .push(" AND deposit_kickoff_utxos.operator_idx = batch.operator_idx;")
        .build()
        .execute(&self.connection)
        .await?;

        Ok(())
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_slash_or_take_sig(
        &self,
        deposit_outpoint: OutPoint,
        kickoff_utxo: UTXO,
    ) -> Result<Option<schnorr::Signature>, BridgeError> {
        let qr: Option<(SignatureDB,)> = sqlx::query_as(
            "SELECT slash_or_take_sig
             FROM deposit_kickoff_utxos
             WHERE deposit_outpoint = $1 AND kickoff_utxo = $2;",
        )
        .bind(OutPointDB(deposit_outpoint))
        .bind(sqlx::types::Json(UtxoDB {
            outpoint_db: OutPointDB(kickoff_utxo.outpoint),
            txout_db: TxOutDB(kickoff_utxo.txout),
        }))
        .fetch_optional(&self.connection)
        .await?;

        match qr {
            Some(sig) => Ok(Some(sig.0 .0)),
            None => Ok(None),
        }
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_deposit_kickoff_generator_tx(
        &self,
        txid: Txid,
    ) -> Result<Option<(String, usize, usize, Txid)>, BridgeError> {
        let qr: Option<(String, i32, i32, TxidDB)> = sqlx::query_as("SELECT raw_signed_tx, num_kickoffs, cur_unused_kickoff_index, funding_txid FROM deposit_kickoff_generator_txs WHERE txid = $1;")
            .bind(TxidDB(txid))
            .fetch_optional(&self.connection)
            .await?;

        match qr {
            Some((raw_hex, num_kickoffs, cur_unused_kickoff_index, funding_txid)) => Ok(Some((
                raw_hex,
                num_kickoffs as usize,
                cur_unused_kickoff_index as usize,
                funding_txid.0,
            ))),
            None => Ok(None),
        }
    }

    /// Saves a new block to the database, later to be updated by a proof.
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn save_new_block(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        block_hash: block::BlockHash,
        block_header: block::Header,
        block_height: u64,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
                "INSERT INTO header_chain_proofs (block_hash, block_header, prev_block_hash, height) VALUES ($1, $2, $3, $4);",
            )
            .bind(BlockHashDB(block_hash)).bind(BlockHeaderDB(block_header)).bind(BlockHashDB(block_header.prev_blockhash)).bind(block_height as i64);

        match tx {
            Some(tx) => query.execute(&mut **tx).await,
            None => query.execute(&self.connection).await,
        }?;

        Ok(())
    }

    /// Sets a block's proof by referring to it by it's hash.
    #[tracing::instrument(skip(self, tx, proof), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn save_block_proof(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        hash: block::BlockHash,
        proof: Receipt,
    ) -> Result<(), BridgeError> {
        let proof = borsh::to_vec(&proof).map_err(BridgeError::BorshError)?;

        let query = sqlx::query("UPDATE header_chain_proofs SET proof = $1 WHERE block_hash = $2;")
            .bind(proof)
            .bind(BlockHashDB(hash));

        match tx {
            Some(tx) => query.execute(&mut **tx).await,
            None => query.execute(&self.connection).await,
        }?;

        Ok(())
    }

    /// Gets a block's proof by referring to it by it's hash.
    #[tracing::instrument(skip(self, tx), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_block_proof_by_hash(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        hash: block::BlockHash,
    ) -> Result<Option<Receipt>, BridgeError> {
        let query = sqlx::query_as("SELECT proof FROM header_chain_proofs WHERE block_hash = $1;")
            .bind(BlockHashDB(hash));

        let receipt: (Option<Vec<u8>>,) = match tx {
            Some(tx) => query.fetch_one(&mut **tx).await,
            None => query.fetch_one(&self.connection).await,
        }?;
        let receipt = match receipt.0 {
            Some(r) => r,
            None => return Ok(None),
        };

        let receipt: Receipt = borsh::from_slice(&receipt).map_err(BridgeError::BorshError)?;

        Ok(Some(receipt))
    }

    /// Returns a block's hash and header, referring it to by it's height.
    #[tracing::instrument(skip(self, tx), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_block_info_by_height(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        height: u64,
    ) -> Result<(block::BlockHash, block::Header), BridgeError> {
        let query = sqlx::query_as(
            "SELECT block_hash, block_header FROM header_chain_proofs WHERE height = $1;",
        )
        .bind(height as i64);

        let result: (Option<BlockHashDB>, Option<BlockHeaderDB>) = match tx {
            Some(tx) => query.fetch_one(&mut **tx).await,
            None => query.fetch_one(&self.connection).await,
        }?;

        match result {
            (Some(hash), Some(header)) => Ok((hash.0, header.0)),
            _ => Ok((
                // TODO: Do we need to return all zeroed values or an error?
                BlockHash::all_zeros(),
                Header {
                    version: Version::TWO,
                    prev_blockhash: BlockHash::all_zeros(),
                    merkle_root: TxMerkleNode::all_zeros(),
                    time: 0,
                    bits: CompactTarget::default(),
                    nonce: 0,
                },
            )),
        }
    }

    /// Returns a block's hash and header, referring it to by it's height.
    #[tracing::instrument(skip(self, tx), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_block_header(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        block_height: u64,
        block_hash: BlockHash,
    ) -> Result<Option<block::Header>, BridgeError> {
        let query = sqlx::query_as(
            "SELECT block_header FROM header_chain_proofs WHERE height = $1 AND block_hash = $2;",
        )
        .bind(block_height as i64)
        .bind(BlockHashDB(block_hash));

        let result: (Option<BlockHeaderDB>,) = match tx {
            Some(tx) => query.fetch_one(&mut **tx).await,
            None => query.fetch_one(&self.connection).await,
        }?;

        match result {
            (Some(block_header),) => Ok(Some(block_header.0)),
            (None,) => Ok(None),
        }
    }

    #[tracing::instrument(skip(self, tx), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_latest_block_info(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
    ) -> Result<(u64, BlockHash), BridgeError> {
        let query = sqlx::query_as(
            "SELECT height, block_hash FROM header_chain_proofs ORDER BY height DESC;",
        );

        let result: (Option<i32>, Option<BlockHashDB>) = match tx {
            Some(tx) => query.fetch_one(&mut **tx).await,
            None => query.fetch_one(&self.connection).await,
        }?;

        match result {
            (Some(height), Some(hash)) => Ok((height as u64, hash.0)),
            _ => Ok((0, BlockHash::all_zeros())),
        }
    }

    #[tracing::instrument(skip(self, tx), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_non_proven_block(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
    ) -> Result<(BlockHash, Header, i32, Receipt), BridgeError> {
        let query = sqlx::query_as(
            "SELECT h1.block_hash,
                    h1.block_header,
                    h1.height,
                    h2.proof
                FROM header_chain_proofs h1
                JOIN header_chain_proofs h2 ON h1.prev_block_hash = h2.block_hash
                WHERE h2.proof IS NOT NULL
                ORDER BY h1.height
                LIMIT 1;",
        );

        let result: (BlockHashDB, BlockHeaderDB, i32, Vec<u8>) = match tx {
            Some(tx) => query.fetch_one(&mut **tx).await,
            None => query.fetch_one(&self.connection).await,
        }?;

        let receipt: Receipt = borsh::from_slice(&result.3).map_err(BridgeError::BorshError)?;

        Ok((result.0 .0, result.1 .0, result.2, receipt))
    }

    /// Sets Winternitz public keys for an operator.
    #[tracing::instrument(skip(self, tx, winternitz_public_key), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn save_watchtower_winternitz_public_keys(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        watchtower_id: u32,
        operator_id: u32,
        winternitz_public_key: Vec<WinternitzPublicKey>,
    ) -> Result<(), BridgeError> {
        let wpk = borsh::to_vec(&winternitz_public_key).map_err(BridgeError::BorshError)?;

        let query = sqlx::query(
            "INSERT INTO watchtower_winternitz_public_keys (watchtower_id, operator_id, winternitz_public_keys) VALUES ($1, $2, $3);",
        )
        .bind(watchtower_id as i64)
        .bind(operator_id as i64)
        .bind(wpk);

        match tx {
            Some(tx) => query.execute(&mut **tx).await,
            None => query.execute(&self.connection).await,
        }?;

        Ok(())
    }

    /// Gets Winternitz public keys for every sequential collateral tx of an operator and a watchtower.
    //#[tracing::instrument(skip(self, tx), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_watchtower_winternitz_public_keys(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        watchtower_id: u32,
        operator_id: u32,
    ) -> Result<Vec<winternitz::PublicKey>, BridgeError> {
        let query = sqlx::query_as(
            "SELECT winternitz_public_keys FROM watchtower_winternitz_public_keys WHERE operator_id = $1 AND watchtower_id = $2;",
        )
        .bind(operator_id as i64)
        .bind(watchtower_id as i64);

        let wpks: (Vec<u8>,) = match tx {
            Some(tx) => query.fetch_one(&mut **tx).await,
            None => query.fetch_one(&self.connection).await,
        }?;

        let watchtower_winternitz_public_keys: Vec<winternitz::PublicKey> =
            borsh::from_slice(&wpks.0).map_err(BridgeError::BorshError)?;

        Ok(watchtower_winternitz_public_keys)
    }

    // TODO: Document
    pub async fn save_watchtower_challenge_addresses(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        watchtower_id: u32,
        operator_id: u32,
        watchtower_challenge_addresses: impl AsRef<[ScriptBuf]>,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
        "INSERT INTO watchtower_challenge_addresses (watchtower_id, operator_id, challenge_addresses)
         VALUES ($1, $2, $3)
         ON CONFLICT (watchtower_id, operator_id) DO UPDATE
         SET challenge_addresses = EXCLUDED.challenge_addresses;",
    )
    .bind(watchtower_id as i64)
    .bind(operator_id as i64)
    .bind(watchtower_challenge_addresses.as_ref().iter().map(|addr| addr.as_ref()).collect::<Vec<&[u8]>>());

        match tx {
            Some(tx) => query.execute(&mut **tx).await,
            None => query.execute(&self.connection).await,
        }?;

        Ok(())
    }

    // TODO: Document
    pub async fn get_watchtower_challenge_addresses(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        watchtower_id: u32,
        operator_id: u32,
    ) -> Result<Vec<ScriptBuf>, BridgeError> {
        let query = sqlx::query_as::<_, (Vec<Vec<u8>>,)>(
            "SELECT challenge_addresses 
         FROM watchtower_challenge_addresses 
         WHERE watchtower_id = $1 AND operator_id = $2;",
        )
        .bind(watchtower_id as i64)
        .bind(operator_id as i64);

        let result = match tx {
            Some(tx) => query.fetch_optional(&mut **tx).await?,
            None => query.fetch_optional(&self.connection).await?,
        };

        match result {
            Some((challenge_addresses,)) => {
                let challenge_addresses: Vec<ScriptBuf> = challenge_addresses
                    .into_iter()
                    .map(|addr| addr.into())
                    .collect();
                Ok(challenge_addresses)
            }
            None => Err(BridgeError::WatchtowerChallengeAddressesNotFound(
                watchtower_id,
                operator_id,
            )),
        }
    }

    /// Sets xonly public key of a watchtoer.
    #[tracing::instrument(skip(self, tx), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn save_watchtower_xonly_pk(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        watchtower_id: u32,
        xonly_pk: &XOnlyPublicKey,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "INSERT INTO watchtower_xonly_public_keys (watchtower_id, xonly_pk) VALUES ($1, $2);",
        )
        .bind(watchtower_id as i64)
        .bind(xonly_pk.serialize());

        match tx {
            Some(tx) => query.execute(&mut **tx).await,
            None => query.execute(&self.connection).await,
        }?;

        Ok(())
    }

    /// Gets xonly public keys of all watchtowers.
    #[tracing::instrument(skip(self, tx), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_all_watchtowers_xonly_pks(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
    ) -> Result<Vec<XOnlyPublicKey>, BridgeError> {
        let query = sqlx::query_as(
            "SELECT xonly_pk FROM watchtower_xonly_public_keys ORDER BY watchtower_id;",
        );

        let rows: Vec<(Vec<u8>,)> = match tx {
            Some(tx) => query.fetch_all(&mut **tx).await,
            None => query.fetch_all(&self.connection).await,
        }?;

        rows.into_iter()
            .map(|xonly_pk| {
                XOnlyPublicKey::from_slice(&xonly_pk.0)
                    .map_err(|e| BridgeError::Error(format!("Can't convert xonly pubkey: {}", e)))
            })
            .collect()
    }

    /// Gets xonly public key of a single watchtower
    #[tracing::instrument(skip(self, tx), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_watchtower_xonly_pk(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        watchtower_id: u32,
    ) -> Result<XOnlyPublicKey, BridgeError> {
        let query = sqlx::query_as(
            "SELECT xonly_pk FROM watchtower_xonly_public_keys WHERE watchtower_id = $1;",
        )
        .bind(watchtower_id as i64);

        let xonly_key: (Vec<u8>,) = match tx {
            Some(tx) => query.fetch_one(&mut **tx).await,
            None => query.fetch_one(&self.connection).await,
        }?;

        Ok(XOnlyPublicKey::from_slice(&xonly_key.0)?)
    }

    /// Saves the deposit signatures to the database for a single operator.
    /// The signatures array is identified by the deposit_outpoint and operator_idx.
    /// For the order of signatures, please check [`crate::builder::sighash::create_nofn_sighash_stream`]
    /// which determines the order of the sighashes that are signed.
    #[tracing::instrument(skip(self, tx, signatures), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn save_deposit_signatures(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        deposit_outpoint: OutPoint,
        operator_idx: u32,
        signatures: Vec<schnorr::Signature>,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "INSERT INTO deposit_signatures (deposit_outpoint, operator_idx, signatures) VALUES ($1, $2, $3);"
        )
        .bind(OutPointDB(deposit_outpoint))
        .bind(operator_idx as i64)
        .bind(SignaturesDB(signatures));

        match tx {
            Some(tx) => query.execute(&mut **tx).await?,
            None => query.execute(&self.connection).await?,
        };

        Ok(())
    }

    /// Saves BitVM setup data for a specific operator, sequential collateral tx and kickoff index combination
    // #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn save_bitvm_setup(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        operator_idx: i32,
        sequential_collateral_tx_idx: i32,
        kickoff_idx: i32,
        assert_tx_addrs: impl AsRef<[ScriptBuf]>,
        root_hash: &[u8; 32],
        public_input_wots: impl AsRef<[[u8; 20]]>,
    ) -> Result<(), BridgeError> {
        // Convert public_input_wots Vec<[u8; 20]> to Vec<Vec<u8>> for PostgreSQL array compatibility
        let public_input_wots: Vec<Vec<u8>> = public_input_wots
            .as_ref()
            .iter()
            .map(|arr| arr.to_vec())
            .collect();

        let query = sqlx::query(
            "INSERT INTO bitvm_setups (operator_idx, sequential_collateral_tx_idx, kickoff_idx, assert_tx_addrs, root_hash, public_input_wots)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (operator_idx, sequential_collateral_tx_idx, kickoff_idx) DO UPDATE
             SET assert_tx_addrs = EXCLUDED.assert_tx_addrs,
                 root_hash = EXCLUDED.root_hash,
                 public_input_wots = EXCLUDED.public_input_wots;"
        )
        .bind(operator_idx)
        .bind(sequential_collateral_tx_idx)
        .bind(kickoff_idx)
        .bind(assert_tx_addrs.as_ref().iter().map(|addr| addr.as_ref()).collect::<Vec<&[u8]>>())
        .bind(root_hash.to_vec())
        .bind(&public_input_wots);

        match tx {
            Some(tx) => query.execute(&mut **tx).await?,
            None => query.execute(&self.connection).await?,
        };

        Ok(())
    }

    /// Retrieves the deposit signatures for a single operator.
    /// The signatures array is identified by the deposit_outpoint and operator_idx.
    /// For the order of signatures, please check [`crate::builder::sighash::create_nofn_sighash_stream`]
    /// which determines the order of the sighashes that are signed.
    #[tracing::instrument(skip(self, tx), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_deposit_signatures(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        deposit_outpoint: OutPoint,
        operator_idx: u32,
    ) -> Result<Option<Vec<schnorr::Signature>>, BridgeError> {
        let query = sqlx::query_as(
            "SELECT signatures FROM deposit_signatures WHERE deposit_outpoint = $1 AND operator_idx = $2;"
        )
        .bind(OutPointDB(deposit_outpoint))
        .bind(operator_idx as i64);

        let result: Result<(SignaturesDB,), sqlx::Error> = match tx {
            Some(tx) => query.fetch_one(&mut **tx).await,
            None => query.fetch_one(&self.connection).await,
        };

        match result {
            Ok((SignaturesDB(signatures),)) => Ok(Some(signatures)),
            Err(sqlx::Error::RowNotFound) => Ok(None),
            Err(e) => Err(BridgeError::DatabaseError(e)),
        }
    }

    /// Retrieves BitVM setup data for a specific operator, sequential collateral tx and kickoff index combination
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_bitvm_setup(
        &self,
        tx: Option<&mut sqlx::Transaction<'_, Postgres>>,
        operator_idx: i32,
        sequential_collateral_tx_idx: i32,
        kickoff_idx: i32,
    ) -> Result<Option<BitvmSetup>, BridgeError> {
        let query = sqlx::query_as::<_, (Vec<Vec<u8>>, Vec<u8>, Vec<Vec<u8>>)>(
            "SELECT assert_tx_addrs, root_hash, public_input_wots
             FROM bitvm_setups
             WHERE operator_idx = $1 AND sequential_collateral_tx_idx = $2 AND kickoff_idx = $3;",
        )
        .bind(operator_idx)
        .bind(sequential_collateral_tx_idx)
        .bind(kickoff_idx);

        let result = match tx {
            Some(tx) => query.fetch_optional(&mut **tx).await?,
            None => query.fetch_optional(&self.connection).await?,
        };

        match result {
            Some((assert_tx_addrs, root_hash, public_input_wots)) => {
                // Convert root_hash Vec<u8> back to [u8; 32]
                let mut root_hash_array = [0u8; 32];
                root_hash_array.copy_from_slice(&root_hash);

                // Convert public_input_wots Vec<Vec<u8>> back to Vec<[u8; 20]>
                let public_input_wots: Result<Vec<[u8; 20]>, _> = public_input_wots
                    .into_iter()
                    .map(|v| {
                        let mut arr = [0u8; 20];
                        if v.len() != 20 {
                            return Err(BridgeError::Error(
                                "Invalid public_input_wots length".to_string(),
                            ));
                        }
                        arr.copy_from_slice(&v);
                        Ok(arr)
                    })
                    .collect();

                let assert_tx_addrs: Vec<ScriptBuf> = assert_tx_addrs
                    .into_iter()
                    .map(|addr| addr.into())
                    .collect();

                Ok(Some((assert_tx_addrs, root_hash_array, public_input_wots?)))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Database;
    use crate::{config::BridgeConfig, initialize_database, utils::initialize_logger};
    use crate::{create_test_config_with_thread_name, UTXO};
    use bitcoin::key::{Keypair, Secp256k1};
    use bitcoin::{
        block::{self, Header, Version},
        BlockHash, CompactTarget, TxMerkleNode,
    };
    use bitcoin::{hashes::Hash, Amount, OutPoint, ScriptBuf, TxOut, Txid, XOnlyPublicKey};
    use bitvm::signatures::winternitz::{self};
    use borsh::BorshDeserialize;
    use risc0_zkvm::Receipt;
    use secp256k1::rand;
    use std::{env, thread};

    #[tokio::test]
    async fn test_operators_funding_utxo_1() {
        let config = create_test_config_with_thread_name!(None);
        let db = Database::new(&config).await.unwrap();

        let utxo = UTXO {
            outpoint: OutPoint {
                txid: Txid::from_byte_array([1u8; 32]),
                vout: 1,
            },
            txout: TxOut {
                value: Amount::from_sat(100),
                script_pubkey: ScriptBuf::from(vec![1u8]),
            },
        };
        db.set_funding_utxo(None, utxo.clone()).await.unwrap();
        let db_utxo = db.get_funding_utxo(None).await.unwrap().unwrap();

        // Sanity check
        assert_eq!(db_utxo, utxo);
    }

    #[tokio::test]
    async fn test_operators_funding_utxo_2() {
        let config = create_test_config_with_thread_name!(None);
        let db = Database::new(&config).await.unwrap();

        let db_utxo = db.get_funding_utxo(None).await.unwrap();

        assert!(db_utxo.is_none());
    }

    #[tokio::test]
    async fn test_deposit_kickoff_generator_tx_2() {
        let config = create_test_config_with_thread_name!(None);
        let db = Database::new(&config).await.unwrap();

        let txid = Txid::from_byte_array([1u8; 32]);
        let res = db.get_deposit_kickoff_generator_tx(txid).await.unwrap();
        assert!(res.is_none());
    }

    #[tokio::test]
    async fn test_deposit_kickoff_generator_tx_3() {
        let config = create_test_config_with_thread_name!(None);
        let db = Database::new(&config).await.unwrap();

        let txid = Txid::from_byte_array([1u8; 32]);
        let res = db.get_deposit_kickoff_generator_tx(txid).await.unwrap();
        assert!(res.is_none());
    }

    #[tokio::test]
    async fn save_get_new_block() {
        let config = create_test_config_with_thread_name!(None);
        let db = Database::new(&config).await.unwrap();

        let block = block::Block {
            header: Header {
                version: Version::TWO,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0,
                bits: CompactTarget::default(),
                nonce: 0,
            },
            txdata: vec![],
        };
        let block_hash = block.block_hash();
        let height = 0x45;

        db.save_new_block(None, block_hash, block.header, height)
            .await
            .unwrap();

        let (read_block_hash, read_block_header) =
            db.get_block_info_by_height(None, height).await.unwrap();
        assert_eq!(block_hash, read_block_hash);
        assert_eq!(block.header, read_block_header);
    }

    #[tokio::test]
    async fn get_block_header() {
        let config = create_test_config_with_thread_name!(None);
        let db = Database::new(&config).await.unwrap();

        let block = block::Block {
            header: Header {
                version: Version::TWO,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0,
                bits: CompactTarget::default(),
                nonce: 0,
            },
            txdata: vec![],
        };
        let block_hash = block.block_hash();
        let block_header = block.header;
        let block_height = 0x45;

        assert!(db
            .get_block_header(None, block_height, block_hash)
            .await
            .is_err());

        db.save_new_block(None, block_hash, block_header, block_height)
            .await
            .unwrap();
        assert_eq!(
            db.get_block_header(None, block_height, block_hash)
                .await
                .unwrap()
                .unwrap(),
            block_header
        );
    }

    #[tokio::test]
    pub async fn get_latest_chain_proof_height() {
        let config = create_test_config_with_thread_name!(None);
        let db = Database::new(&config).await.unwrap();

        let mut block = block::Block {
            header: Header {
                version: Version::TWO,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0,
                bits: CompactTarget::default(),
                nonce: 0,
            },
            txdata: vec![],
        };

        assert!(db.get_latest_block_info(None).await.is_err());

        // Adding a new block should return a height.
        let height = 0x1F;
        let hash = block.block_hash();
        db.save_new_block(None, hash, block.header, height)
            .await
            .unwrap();
        assert_eq!(
            (height, hash),
            db.get_latest_block_info(None).await.unwrap()
        );

        // Adding a new block with smaller height should not effect what's
        // getting returned.
        let smaller_height = height - 1;
        block.header.time = 1; // To avoid same block hash.
        db.save_new_block(None, block.block_hash(), block.header, smaller_height)
            .await
            .unwrap();
        assert_eq!(
            (height, hash),
            db.get_latest_block_info(None).await.unwrap()
        );

        // Adding another block with higher height should return a different
        // height.
        let height = 0x45;
        block.header.time = 2; // To avoid same block hash.
        let hash = block.block_hash();
        db.save_new_block(None, hash, block.header, height)
            .await
            .unwrap();
        assert_eq!(
            (height, hash),
            db.get_latest_block_info(None).await.unwrap()
        );
    }

    #[tokio::test]
    pub async fn save_get_block_proof() {
        let config = create_test_config_with_thread_name!(None);
        let db = Database::new(&config).await.unwrap();

        // Save dummy block.
        let block = block::Block {
            header: Header {
                version: Version::TWO,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0x1F,
                bits: CompactTarget::default(),
                nonce: 0x45,
            },
            txdata: vec![],
        };
        let block_hash = block.block_hash();
        let height = 0x45;
        db.save_new_block(None, block_hash, block.header, height)
            .await
            .unwrap();

        // Requesting proof for an existing block without a proof should
        // return `None`.
        let read_receipt = db.get_block_proof_by_hash(None, block_hash).await.unwrap();
        assert!(read_receipt.is_none());

        // Update it with a proof.
        let receipt =
            Receipt::try_from_slice(include_bytes!("../../tests/data/first_1.bin")).unwrap();
        db.save_block_proof(None, block_hash, receipt.clone())
            .await
            .unwrap();

        let read_receipt = db
            .get_block_proof_by_hash(None, block_hash)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(receipt.journal, read_receipt.journal);
        assert_eq!(receipt.metadata, read_receipt.metadata);
    }

    #[tokio::test]
    pub async fn get_non_proven_block() {
        let config = create_test_config_with_thread_name!(None);
        let db = Database::new(&config).await.unwrap();

        assert!(db.get_non_proven_block(None).await.is_err());

        let base_height = 0x45;

        // Save initial block without a proof.
        let block = block::Block {
            header: Header {
                version: Version::TWO,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0x1F,
                bits: CompactTarget::default(),
                nonce: 0x45,
            },
            txdata: vec![],
        };
        let block_hash = block.block_hash();
        let height = base_height;
        db.save_new_block(None, block_hash, block.header, height)
            .await
            .unwrap();
        assert!(db.get_non_proven_block(None).await.is_err());

        // Save second block with a proof.
        let block = block::Block {
            header: Header {
                version: Version::TWO,
                prev_blockhash: block_hash,
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0x1F,
                bits: CompactTarget::default(),
                nonce: 0x45 + 1,
            },
            txdata: vec![],
        };
        let block_hash1 = block.block_hash();
        let height1 = base_height + 1;
        db.save_new_block(None, block_hash1, block.header, height1)
            .await
            .unwrap();
        let receipt =
            Receipt::try_from_slice(include_bytes!("../../tests/data/first_1.bin")).unwrap();
        db.save_block_proof(None, block_hash1, receipt.clone())
            .await
            .unwrap();
        assert!(db.get_non_proven_block(None).await.is_err());

        // Save third block without a proof.
        let block = block::Block {
            header: Header {
                version: Version::TWO,
                prev_blockhash: block_hash1,
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0x1F,
                bits: CompactTarget::default(),
                nonce: 0x45 + 3,
            },
            txdata: vec![],
        };
        let block_hash2 = block.block_hash();
        let height2 = base_height + 2;
        db.save_new_block(None, block_hash2, block.header, height2)
            .await
            .unwrap();

        // This time, `get_non_proven_block` should return second block's details.
        let res = db.get_non_proven_block(None).await.unwrap();
        assert_eq!(res.0, block_hash2);
        assert_eq!(res.2 as u64, height2);
    }

    #[tokio::test]
    async fn save_get_winternitz_public_key() {
        let config = create_test_config_with_thread_name!(None);
        let database = Database::new(&config).await.unwrap();

        // Assuming there are 2 sequential collateral txs.
        let wpk0: winternitz::PublicKey = vec![[0x45; 20], [0x1F; 20]];
        let wpk1: winternitz::PublicKey = vec![[0x12; 20], [0x34; 20]];
        let watchtower_winternitz_public_keys = vec![wpk0.clone(), wpk1.clone()];

        database
            .save_watchtower_winternitz_public_keys(
                None,
                0x45,
                0x1F,
                watchtower_winternitz_public_keys.clone(),
            )
            .await
            .unwrap();

        let read_wpks = database
            .get_watchtower_winternitz_public_keys(None, 0x45, 0x1F)
            .await
            .unwrap();

        assert_eq!(watchtower_winternitz_public_keys.len(), read_wpks.len());
        assert_eq!(wpk0, read_wpks[0]);
        assert_eq!(wpk1, read_wpks[1]);
    }

    #[tokio::test]
    async fn save_get_watchtower_challenge_address() {
        let config = create_test_config_with_thread_name!(None);
        let database = Database::new(&config).await.unwrap();

        // Assuming there are 2 time_txs.
        let address_0: ScriptBuf = ScriptBuf::from_bytes([0x45; 34].to_vec());
        let address_1: ScriptBuf = ScriptBuf::from_bytes([0x12; 34].to_vec());
        let watchtower_winternitz_public_keys = vec![address_0.clone(), address_1.clone()];

        database
            .save_watchtower_challenge_addresses(
                None,
                0x45,
                0x1F,
                watchtower_winternitz_public_keys.clone(),
            )
            .await
            .unwrap();

        let read_addresses = database
            .get_watchtower_challenge_addresses(None, 0x45, 0x1F)
            .await
            .unwrap();

        assert_eq!(
            watchtower_winternitz_public_keys.len(),
            read_addresses.len()
        );
        assert_eq!(address_0, read_addresses[0]);
        assert_eq!(address_1, read_addresses[1]);
    }

    #[tokio::test]
    async fn save_get_watchtower_xonly_pk() {
        let config = create_test_config_with_thread_name!(None);
        let database = Database::new(&config).await.unwrap();

        let secp = Secp256k1::new();
        let keypair1 = Keypair::new(&secp, &mut rand::thread_rng());
        let xonly1 = XOnlyPublicKey::from_keypair(&keypair1).0;

        let keypair2 = Keypair::new(&secp, &mut rand::thread_rng());
        let xonly2 = XOnlyPublicKey::from_keypair(&keypair2).0;

        let w_data = vec![xonly1, xonly2];

        for (id, data) in w_data.iter().enumerate() {
            database
                .save_watchtower_xonly_pk(None, id as u32, data)
                .await
                .unwrap();
        }

        let read_pks = database.get_all_watchtowers_xonly_pks(None).await.unwrap();

        assert_eq!(read_pks, w_data);

        for (id, key) in w_data.iter().enumerate() {
            let read_pk = database
                .get_watchtower_xonly_pk(None, id as u32)
                .await
                .unwrap();
            assert_eq!(read_pk, *key);
        }
    }

    #[tokio::test]
    async fn test_save_get_bitvm_setup() {
        let config = create_test_config_with_thread_name!(None);
        let database = Database::new(&config).await.unwrap();

        let operator_idx = 0;
        let sequential_collateral_tx_idx = 1;
        let kickoff_idx = 2;
        let assert_tx_addrs = [vec![1u8; 34], vec![4u8; 34]];
        let root_hash = [42u8; 32];
        let public_input_wots = vec![[1u8; 20], [2u8; 20]];

        // Save BitVM setup
        database
            .save_bitvm_setup(
                None,
                operator_idx,
                sequential_collateral_tx_idx,
                kickoff_idx,
                assert_tx_addrs
                    .iter()
                    .map(|addr| addr.clone().into())
                    .collect::<Vec<ScriptBuf>>(),
                &root_hash,
                public_input_wots.clone(),
            )
            .await
            .unwrap();

        // Retrieve and verify
        let result = database
            .get_bitvm_setup(
                None,
                operator_idx,
                sequential_collateral_tx_idx,
                kickoff_idx,
            )
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            result.0,
            assert_tx_addrs
                .iter()
                .map(|addr| addr.clone().into())
                .collect::<Vec<ScriptBuf>>()
        );
        assert_eq!(result.1, root_hash);
        assert_eq!(result.2, public_input_wots);

        // Test non-existent entry
        let non_existent = database
            .get_bitvm_setup(None, 999, sequential_collateral_tx_idx, kickoff_idx)
            .await
            .unwrap();
        assert!(non_existent.is_none());
    }
}
