//! # Verifier Related Database Operations
//!
//! This module includes database functions which are mainly used by a verifier.

use super::{wrapper::PublicKeyDB, Database, DatabaseTransaction};
use crate::{errors::BridgeError, execute_query_with_tx};
use bitcoin::secp256k1::PublicKey;
use sqlx::QueryBuilder;

impl Database {
    /// Sets the all verifiers' public keys. Given array **must** be in the same
    /// order as the verifiers' indexes.
    pub async fn set_verifiers_public_keys(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        public_keys: &[PublicKey],
    ) -> Result<(), BridgeError> {
        let mut query = QueryBuilder::new("INSERT INTO verifier_public_keys (idx, public_key) ");
        query.push_values(public_keys.iter().enumerate(), |mut builder, (idx, pk)| {
            builder.push_bind(idx as i32).push_bind(PublicKeyDB(*pk));
        });
        let query = query.build();

        execute_query_with_tx!(self.connection, tx, query, execute)?;

        Ok(())
    }

    pub async fn get_verifiers_public_keys(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
    ) -> Result<Vec<PublicKey>, BridgeError> {
        let query = sqlx::query_as("SELECT * FROM verifier_public_keys ORDER BY idx;");

        let pks: Vec<(i32, PublicKeyDB)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_all)?;

        Ok(pks.into_iter().map(|(_, pk)| pk.0).collect())
    }
}
