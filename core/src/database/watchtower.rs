//! # Watchtower Related Database Operations
//!
//! This module includes database functions which are mainly used by a
//! watchtower.

use super::{Database, DatabaseTransaction};
use crate::errors::BridgeError;
use crate::execute_query_with_tx;
use bitcoin::{ScriptBuf, XOnlyPublicKey};
use bitvm::signatures::winternitz;
use bitvm::signatures::winternitz::PublicKey as WinternitzPublicKey;

impl Database {
    /// Sets winternitz public keys of a watchtower for an operator.
    pub async fn set_watchtower_winternitz_public_keys(
        &self,
        tx: DatabaseTransaction<'_, '_>,
        watchtower_id: u32,
        operator_id: u32,
        winternitz_public_key: Vec<WinternitzPublicKey>,
    ) -> Result<(), BridgeError> {
        let wpk = borsh::to_vec(&winternitz_public_key).map_err(BridgeError::BorshError)?;

        let query = sqlx::query(
            "INSERT INTO watchtower_winternitz_public_keys
            (watchtower_id, operator_id, winternitz_public_keys)
            VALUES ($1, $2, $3);",
        )
        .bind(watchtower_id as i64)
        .bind(operator_id as i64)
        .bind(wpk);

        execute_query_with_tx!(self.connection, tx, query, execute)?;

        Ok(())
    }

    /// Gets the winternitz public keys of a watchtower for every sequential
    /// collateral tx and operator combination.
    pub async fn get_watchtower_winternitz_public_keys(
        &self,
        tx: DatabaseTransaction<'_, '_>,
        watchtower_id: u32,
        operator_id: u32,
    ) -> Result<Vec<winternitz::PublicKey>, BridgeError> {
        let query = sqlx::query_as(
            "SELECT winternitz_public_keys FROM watchtower_winternitz_public_keys WHERE operator_id = $1 AND watchtower_id = $2;",
        )
        .bind(operator_id as i64)
        .bind(watchtower_id as i64);

        let wpks: (Vec<u8>,) = execute_query_with_tx!(self.connection, tx, query, fetch_one)?;

        let watchtower_winternitz_public_keys: Vec<winternitz::PublicKey> =
            borsh::from_slice(&wpks.0).map_err(BridgeError::BorshError)?;

        Ok(watchtower_winternitz_public_keys)
    }

    /// Sets challenge addresses of a watchtower for an operator. If there is an
    /// existing entry, it overwrites it with the new addresses.
    pub async fn set_watchtower_challenge_addresses(
        &self,
        tx: DatabaseTransaction<'_, '_>,
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

        execute_query_with_tx!(self.connection, tx, query, execute)?;

        Ok(())
    }

    /// Gets the challenge addresses of a watchtower for an operator.
    pub async fn get_watchtower_challenge_addresses(
        &self,
        tx: DatabaseTransaction<'_, '_>,
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

        let result = execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

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

    /// Sets xonly public key of a watchtower.
    pub async fn set_watchtower_xonly_pk(
        &self,
        tx: DatabaseTransaction<'_, '_>,
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
        tx: DatabaseTransaction<'_, '_>,
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
        tx: DatabaseTransaction<'_, '_>,
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
    use crate::create_test_config_with_thread_name;
    use crate::{config::BridgeConfig, initialize_database, utils::initialize_logger};
    use bitcoin::key::{Keypair, Secp256k1};
    use bitcoin::{ScriptBuf, XOnlyPublicKey};
    use bitvm::signatures::winternitz::{self};
    use secp256k1::rand;
    use std::{env, thread};

    #[tokio::test]
    async fn set_get_winternitz_public_key() {
        let config = create_test_config_with_thread_name!(None);
        let database = Database::new(&config).await.unwrap();

        // Assuming there are 2 sequential collateral txs.
        let wpk0: winternitz::PublicKey = vec![[0x45; 20], [0x1F; 20]];
        let wpk1: winternitz::PublicKey = vec![[0x12; 20], [0x34; 20]];
        let watchtower_winternitz_public_keys = vec![wpk0.clone(), wpk1.clone()];

        database
            .set_watchtower_winternitz_public_keys(
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
    async fn set_get_watchtower_challenge_address() {
        let config = create_test_config_with_thread_name!(None);
        let database = Database::new(&config).await.unwrap();

        // Assuming there are 2 time_txs.
        let address_0: ScriptBuf = ScriptBuf::from_bytes([0x45; 34].to_vec());
        let address_1: ScriptBuf = ScriptBuf::from_bytes([0x12; 34].to_vec());
        let watchtower_winternitz_public_keys = vec![address_0.clone(), address_1.clone()];

        database
            .set_watchtower_challenge_addresses(
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
    async fn set_get_watchtower_xonly_pk() {
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
