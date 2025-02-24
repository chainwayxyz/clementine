//! # Watchtower Related Database Operations
//!
//! This module includes database functions which are mainly used by a
//! watchtower.

use super::{Database, DatabaseTransaction};
use crate::errors::BridgeError;
use crate::execute_query_with_tx;
use bitcoin::XOnlyPublicKey;
use bitvm::signatures::winternitz;
use bitvm::signatures::winternitz::PublicKey as WinternitzPublicKey;

impl Database {
    /// Sets winternitz public keys of a watchtower for an operator.
    pub async fn set_watchtower_winternitz_public_keys(
        &self,
        mut tx: Option<DatabaseTransaction<'_, '_>>,
        watchtower_id: u32,
        operator_id: u32,
        deposit_outpoint: bitcoin::OutPoint,
        winternitz_public_key: &WinternitzPublicKey,
    ) -> Result<(), BridgeError> {
        let deposit_id = self
            .get_deposit_id(tx.as_deref_mut(), deposit_outpoint)
            .await?;
        let wpk = borsh::to_vec(winternitz_public_key).map_err(BridgeError::BorshError)?;

        let query = sqlx::query(
            "INSERT INTO watchtower_winternitz_public_keys
            (watchtower_id, operator_id, deposit_id, winternitz_public_key)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (watchtower_id, operator_id, deposit_id) DO UPDATE
            SET winternitz_public_key = EXCLUDED.winternitz_public_key;",
        )
        .bind(watchtower_id as i64)
        .bind(operator_id as i64)
        .bind(i32::try_from(deposit_id)?)
        .bind(wpk);

        execute_query_with_tx!(self.connection, tx, query, execute)?;

        Ok(())
    }

    /// Gets the winternitz public keys of a watchtower for every sequential
    /// collateral tx and operator combination.
    pub async fn get_watchtower_winternitz_public_keys(
        &self,
        mut tx: Option<DatabaseTransaction<'_, '_>>,
        watchtower_id: u32,
        operator_id: u32,
        deposit_outpoint: bitcoin::OutPoint,
    ) -> Result<winternitz::PublicKey, BridgeError> {
        let deposit_id = self
            .get_deposit_id(tx.as_deref_mut(), deposit_outpoint)
            .await?;
        let query = sqlx::query_as(
            "SELECT winternitz_public_key FROM watchtower_winternitz_public_keys WHERE operator_id = $1 AND watchtower_id = $2
                AND deposit_id = $3;",
        )
        .bind(operator_id as i64)
        .bind(watchtower_id as i64)
        .bind(i32::try_from(deposit_id)?);

        let wpks: (Vec<u8>,) = execute_query_with_tx!(self.connection, tx, query, fetch_one)?;

        let watchtower_winternitz_public_keys: winternitz::PublicKey =
            borsh::from_slice(&wpks.0).map_err(BridgeError::BorshError)?;

        Ok(watchtower_winternitz_public_keys)
    }

    /// Sets challenge addresses of a watchtower for an operator. If there is an
    /// existing entry, it overwrites it with the new addresses.
    pub async fn set_watchtower_challenge_hash(
        &self,
        mut tx: Option<DatabaseTransaction<'_, '_>>,
        watchtower_id: u32,
        operator_id: u32,
        watchtower_challenge_hash: [u8; 32],
        deposit_outpoint: bitcoin::OutPoint,
    ) -> Result<(), BridgeError> {
        let deposit_id = self
            .get_deposit_id(tx.as_deref_mut(), deposit_outpoint)
            .await?;
        let query = sqlx::query(
        "INSERT INTO watchtower_challenge_hashes (watchtower_id, operator_id, deposit_id, challenge_hash)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (watchtower_id, operator_id, deposit_id) DO UPDATE
         SET challenge_hash = EXCLUDED.challenge_hash;",
        )
        .bind(watchtower_id as i64)
        .bind(operator_id as i64)
            .bind(i32::try_from(deposit_id)?)
        .bind(watchtower_challenge_hash);

        execute_query_with_tx!(self.connection, tx, query, execute)?;

        Ok(())
    }

    /// Gets the challenge addresses of a watchtower for an operator.
    pub async fn get_watchtower_challenge_hash(
        &self,
        mut tx: Option<DatabaseTransaction<'_, '_>>,
        watchtower_id: u32,
        operator_id: u32,
        deposit_outpoint: bitcoin::OutPoint,
    ) -> Result<[u8; 32], BridgeError> {
        let deposit_id = self.get_deposit_id(tx.as_deref_mut(), deposit_outpoint).await?;
        let query = sqlx::query_as::<_, (Vec<u8>,)>(
            "SELECT challenge_hash
         FROM watchtower_challenge_hashes
         WHERE watchtower_id = $1 AND operator_id = $2 and deposit_id = $3;",
        )
        .bind(watchtower_id as i64)
        .bind(operator_id as i64)
        .bind(i32::try_from(deposit_id)?);

        let result = execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

        match result {
            Some((challenge_hash,)) => Ok(challenge_hash.try_into().map_err(|_| {
                BridgeError::Error("Can't convert challenge hash in db to [u8; 32]".to_string())
            })?),
            None => Err(BridgeError::WatchtowerChallengeAddressesNotFound(
                watchtower_id,
                operator_id,
            )),
        }
    }

    /// Sets xonly public key of a watchtower.
    pub async fn set_watchtower_xonly_pk(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        watchtower_id: u32,
        xonly_pk: &XOnlyPublicKey,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "INSERT INTO watchtower_xonly_public_keys (watchtower_id, xonly_pk) VALUES ($1, $2);",
        )
        .bind(watchtower_id as i64)
        .bind(xonly_pk.serialize());

        execute_query_with_tx!(self.connection, tx, query, execute)?;

        Ok(())
    }

    /// Gets xonly public key of a watchtower.
    pub async fn get_watchtower_xonly_pk(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        watchtower_id: u32,
    ) -> Result<XOnlyPublicKey, BridgeError> {
        let query = sqlx::query_as(
            "SELECT xonly_pk FROM watchtower_xonly_public_keys WHERE watchtower_id = $1;",
        )
        .bind(watchtower_id as i64);

        let xonly_key: (Vec<u8>,) = execute_query_with_tx!(self.connection, tx, query, fetch_one)?;

        Ok(XOnlyPublicKey::from_slice(&xonly_key.0)?)
    }

    /// Gets xonly public keys of all watchtowers.
    pub async fn get_all_watchtowers_xonly_pks(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
    ) -> Result<Vec<XOnlyPublicKey>, BridgeError> {
        let query = sqlx::query_as(
            "SELECT xonly_pk FROM watchtower_xonly_public_keys ORDER BY watchtower_id;",
        );

        let rows: Vec<(Vec<u8>,)> = execute_query_with_tx!(self.connection, tx, query, fetch_all)?;

        rows.into_iter()
            .map(|xonly_pk| {
                XOnlyPublicKey::from_slice(&xonly_pk.0)
                    .map_err(|e| BridgeError::Error(format!("Can't convert xonly pubkey: {}", e)))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Database;
    use crate::test::common::*;
    use bitcoin::hashes::Hash;
    use bitcoin::key::{Keypair, Secp256k1};
    use bitcoin::{Txid, XOnlyPublicKey};
    use bitvm::signatures::winternitz::{self};
    use secp256k1::rand;

    #[tokio::test]
    async fn set_get_winternitz_public_key() {
        let config = create_test_config_with_thread_name(None).await;
        let database = Database::new(&config).await.unwrap();

        // Assuming there are 2 sequential collateral txs.
        let wpk0: winternitz::PublicKey = vec![[0x45; 20], [0x1F; 20]];
        let deposit_outpoint = bitcoin::OutPoint::new(Txid::all_zeros(), 0x1F);

        database
            .set_watchtower_winternitz_public_keys(None, 0x45, 0x1F, deposit_outpoint, &wpk0)
            .await
            .unwrap();

        let read_wpks = database
            .get_watchtower_winternitz_public_keys(None, 0x45, 0x1F, deposit_outpoint)
            .await
            .unwrap();

        assert_eq!(wpk0, read_wpks);
    }

    #[tokio::test]
    async fn set_get_watchtower_challenge_address() {
        let config = create_test_config_with_thread_name(None).await;
        let database = Database::new(&config).await.unwrap();

        // Assuming there are 2 time_txs.
        let challenge_hash = [1u8; 32];

        database
            .set_watchtower_challenge_hash(
                None,
                0x45,
                0x1F,
                challenge_hash,
                bitcoin::OutPoint::new(Txid::all_zeros(), 0x1F),
            )
            .await
            .unwrap();

        let read_hash = database
            .get_watchtower_challenge_hash(
                None,
                0x45,
                0x1F,
                bitcoin::OutPoint::new(Txid::all_zeros(), 0x1F),
            )
            .await
            .unwrap();

        assert_eq!(challenge_hash, read_hash);
    }

    #[tokio::test]
    async fn set_get_watchtower_xonly_pk() {
        let config = create_test_config_with_thread_name(None).await;
        let database = Database::new(&config).await.unwrap();

        let secp = Secp256k1::new();
        let keypair1 = Keypair::new(&secp, &mut rand::thread_rng());
        let xonly1 = XOnlyPublicKey::from_keypair(&keypair1).0;

        let keypair2 = Keypair::new(&secp, &mut rand::thread_rng());
        let xonly2 = XOnlyPublicKey::from_keypair(&keypair2).0;

        let w_data = vec![xonly1, xonly2];

        for (id, data) in w_data.iter().enumerate() {
            database
                .set_watchtower_xonly_pk(None, id as u32, data)
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
}
