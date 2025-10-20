//! # State Machine Related Database Operations
//!
//! This module includes database functions for persisting and loading state machines.

use bitcoin::XOnlyPublicKey;

use super::{wrapper::XOnlyPublicKeyDB, Database, DatabaseTransaction};
use crate::errors::BridgeError;
use crate::execute_query_with_tx;

impl Database {
    /// Saves state machines to the database with the current block height
    ///
    /// # Arguments
    ///
    /// * `tx` - Optional database transaction
    /// * `kickoff_machines` - Vector of (state_json, kickoff_id, owner_type) tuples for kickoff machines
    /// * `round_machines` - Vector of (state_json, operator_xonly_pk, owner_type) tuples for round machines
    /// * `block_height` - Current block height
    ///
    /// # Errors
    ///
    /// Returns a `BridgeError` if the database operation fails
    pub async fn save_state_machines(
        &self,
        tx: DatabaseTransaction<'_, '_>,
        kickoff_machines: Vec<(String, String)>,
        round_machines: Vec<(String, XOnlyPublicKey)>,
        block_height: i32,
        owner_type: &str,
    ) -> Result<(), BridgeError> {
        // Save kickoff machines that are dirty
        for (state_json, kickoff_id) in kickoff_machines {
            let query = sqlx::query(
                "INSERT INTO state_machines (
                    machine_type,
                    state_json,
                    kickoff_id,
                    owner_type,
                    block_height,
                    created_at,
                    updated_at
                ) VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
                ON CONFLICT (machine_type, kickoff_id, owner_type)
                DO UPDATE SET
                    state_json = EXCLUDED.state_json,
                    block_height = EXCLUDED.block_height,
                    updated_at = NOW()",
            )
            .bind("kickoff")
            .bind(&state_json)
            .bind(kickoff_id)
            .bind(owner_type)
            .bind(block_height);

            query.execute(&mut **tx).await?;
        }

        // Save round machines that are dirty
        for (state_json, operator_xonly_pk) in round_machines {
            let query = sqlx::query(
                "INSERT INTO state_machines (
                    machine_type,
                    state_json,
                    operator_xonly_pk,
                    owner_type,
                    block_height,
                    created_at,
                    updated_at
                ) VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
                ON CONFLICT (machine_type, operator_xonly_pk, owner_type)
                DO UPDATE SET
                    state_json = EXCLUDED.state_json,
                    block_height = EXCLUDED.block_height,
                    updated_at = NOW()",
            )
            .bind("round")
            .bind(&state_json)
            .bind(XOnlyPublicKeyDB(operator_xonly_pk))
            .bind(owner_type)
            .bind(block_height);

            query.execute(&mut **tx).await?;
        }

        // Update state manager status
        let query = sqlx::query(
            "INSERT INTO state_manager_status (
                owner_type,
                next_height_to_process,
                updated_at
            ) VALUES ($1, $2, NOW())
            ON CONFLICT (owner_type)
            DO UPDATE SET
                next_height_to_process = EXCLUDED.next_height_to_process,
                updated_at = NOW()",
        )
        .bind(owner_type)
        .bind(block_height);

        query.execute(&mut **tx).await?;

        Ok(())
    }

    /// Gets the last processed block height
    ///
    /// # Arguments
    ///
    /// * `tx` - Optional database transaction
    ///
    /// # Errors
    ///
    /// Returns a `BridgeError` if the database operation fails
    pub async fn get_next_height_to_process(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        owner_type: &str,
    ) -> Result<Option<i32>, BridgeError> {
        let query = sqlx::query_as(
            "SELECT next_height_to_process FROM state_manager_status WHERE owner_type = $1",
        )
        .bind(owner_type);

        let result: Option<(i32,)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

        Ok(result.map(|(height,)| height))
    }

    /// Loads kickoff machines from the database
    ///
    /// # Arguments
    ///
    /// * `tx` - Optional database transaction
    /// * `owner_type` - The owner type to filter by
    ///
    /// # Errors
    ///
    /// Returns a `BridgeError` if the database operation fails
    pub async fn load_kickoff_machines(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        owner_type: &str,
    ) -> Result<Vec<(String, String, i32)>, BridgeError> {
        let query = sqlx::query_as(
            "SELECT
                state_json,
                kickoff_id,
                block_height
            FROM state_machines
            WHERE machine_type = 'kickoff' AND owner_type = $1",
        )
        .bind(owner_type);

        let results = execute_query_with_tx!(self.connection, tx, query, fetch_all)?;

        Ok(results)
    }

    /// Loads round machines from the database
    ///
    /// # Arguments
    ///
    /// * `tx` - Optional database transaction
    /// * `owner_type` - The owner type to filter by
    ///
    /// # Errors
    ///
    /// Returns a `BridgeError` if the database operation fails
    pub async fn load_round_machines(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        owner_type: &str,
    ) -> Result<Vec<(String, XOnlyPublicKey, i32)>, BridgeError> {
        let query = sqlx::query_as(
            "SELECT
                state_json,
                operator_xonly_pk,
                block_height
            FROM state_machines
            WHERE machine_type = 'round' AND owner_type = $1",
        )
        .bind(owner_type);

        let results: Vec<(String, XOnlyPublicKeyDB, i32)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_all)?;

        Ok(results
            .into_iter()
            .map(|(state_json, operator_xonly_pk, block_height)| {
                (state_json, operator_xonly_pk.0, block_height)
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::common::*;

    #[tokio::test]
    async fn test_save_and_load_state_machines() {
        let config = create_test_config_with_thread_name().await;
        let db = Database::new(&config).await.unwrap();

        let xonly_pk1 = generate_random_xonly_pk();
        let xonly_pk2 = generate_random_xonly_pk();

        // Create test data with owner_type
        let owner_type = "test_owner";
        let kickoff_machines = vec![
            ("kickoff_state_1".to_string(), "kickoff_id_1".to_string()),
            ("kickoff_state_2".to_string(), "kickoff_id_2".to_string()),
        ];

        let round_machines = vec![
            ("round_state_1".to_string(), xonly_pk1),
            ("round_state_2".to_string(), xonly_pk2),
        ];

        let mut dbtx = db.begin_transaction().await.unwrap();
        // Save state machines
        db.save_state_machines(
            &mut dbtx,
            kickoff_machines.clone(),
            round_machines.clone(),
            123,
            owner_type,
        )
        .await
        .unwrap();
        dbtx.commit().await.unwrap();

        // Check last processed block height
        let block_height = db
            .get_next_height_to_process(None, owner_type)
            .await
            .unwrap();
        assert_eq!(block_height, Some(123));

        // Load kickoff machines
        let loaded_kickoff = db.load_kickoff_machines(None, owner_type).await.unwrap();
        assert_eq!(loaded_kickoff.len(), 2);
        assert_eq!(loaded_kickoff[0].0, "kickoff_state_1");
        assert_eq!(loaded_kickoff[0].1, "kickoff_id_1");
        assert_eq!(loaded_kickoff[0].2, 123);

        // Load round machines
        let loaded_round = db.load_round_machines(None, owner_type).await.unwrap();
        assert_eq!(loaded_round.len(), 2);
        assert_eq!(loaded_round[0].0, "round_state_1");
        assert_eq!(loaded_round[0].1, xonly_pk1);
        assert_eq!(loaded_round[0].2, 123);
    }
}
