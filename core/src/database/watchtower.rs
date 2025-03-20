//! # Watchtower Related Database Operations
//!
//! This module includes database functions which are mainly used by a
//! watchtower.

use super::{Database, DatabaseTransaction};
use crate::errors::BridgeError;
use crate::execute_query_with_tx;
use bitcoin::XOnlyPublicKey;

impl Database {
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
    use bitcoin::key::{Keypair, Secp256k1};
    use bitcoin::XOnlyPublicKey;
    use secp256k1::rand;

    #[tokio::test]
    async fn set_get_watchtower_xonly_pk() {
        let config = create_test_config_with_thread_name().await;
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
