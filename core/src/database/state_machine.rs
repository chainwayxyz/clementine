//! # State Machine Related Database Operations
//!
//! This module includes database functions for persisting and loading state machines.

use super::{Database, DatabaseTransaction};
use crate::errors::BridgeError;
use crate::execute_query_with_tx;

impl Database {
    /// Saves state machines to the database with the current block height
    ///
    /// # Arguments
    ///
    /// * `tx` - Optional database transaction
    /// * `kickoff_machines` - Vector of (state_json, kickoff_id, owner_type, dirty) tuples for kickoff machines
    /// * `round_machines` - Vector of (state_json, operator_idx, owner_type, dirty) tuples for round machines
    /// * `block_height` - Current block height
    ///
    /// # Errors
    ///
    /// Returns a `BridgeError` if the database operation fails
    pub async fn save_state_machines(
        &self,
        mut tx: Option<DatabaseTransaction<'_, '_>>,
        kickoff_machines: Vec<(String, String, String, bool)>,
        round_machines: Vec<(String, i32, String, bool)>,
        block_height: i32,
    ) -> Result<(), BridgeError> {
        // Save kickoff machines that are dirty
        for (state_json, kickoff_id, owner_type, dirty) in kickoff_machines {
            // Skip machines that are not dirty
            if !dirty {
                continue;
            }

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
            .bind(&owner_type)
            .bind(block_height);

            execute_query_with_tx!(self.connection, tx.as_deref_mut(), query, execute)?;
        }

        // Save round machines that are dirty
        for (state_json, operator_idx, owner_type, dirty) in round_machines {
            // Skip machines that are not dirty
            if !dirty {
                continue;
            }

            let query = sqlx::query(
                "INSERT INTO state_machines (
                    machine_type,
                    state_json,
                    operator_idx,
                    owner_type,
                    block_height,
                    created_at,
                    updated_at
                ) VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
                ON CONFLICT (machine_type, operator_idx, owner_type)
                DO UPDATE SET
                    state_json = EXCLUDED.state_json,
                    block_height = EXCLUDED.block_height,
                    updated_at = NOW()",
            )
            .bind("round")
            .bind(&state_json)
            .bind(operator_idx)
            .bind(&owner_type)
            .bind(block_height);

            execute_query_with_tx!(self.connection, tx.as_deref_mut(), query, execute)?;
        }

        // Update state manager status
        let query = sqlx::query(
            "INSERT INTO state_manager_status (
                id,
                last_processed_block_height,
                updated_at
            ) VALUES (1, $1, NOW())
            ON CONFLICT (id)
            DO UPDATE SET
                last_processed_block_height = EXCLUDED.last_processed_block_height,
                updated_at = NOW()",
        )
        .bind(block_height);

        execute_query_with_tx!(self.connection, tx, query, execute)?;

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
    pub async fn get_last_processed_block_height(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
    ) -> Result<Option<i32>, BridgeError> {
        let query = sqlx::query_as(
            "SELECT last_processed_block_height FROM state_manager_status WHERE id = 1",
        );

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
    ) -> Result<Vec<(String, i32, i32)>, BridgeError> {
        let query = sqlx::query_as(
            "SELECT
                state_json,
                operator_idx,
                block_height
            FROM state_machines
            WHERE machine_type = 'round' AND owner_type = $1",
        )
        .bind(owner_type);

        let results = execute_query_with_tx!(self.connection, tx, query, fetch_all)?;

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::common::*;

    #[tokio::test]
    async fn test_save_and_load_state_machines() {
        let config = create_test_config_with_thread_name(None).await;
        let db = Database::new(&config).await.unwrap();

        // Create test data with owner_type
        let owner_type = "test_owner";
        let kickoff_machines = vec![
            (
                "kickoff_state_1".to_string(),
                "kickoff_id_1".to_string(),
                owner_type.to_string(),
                true, // dirty
            ),
            (
                "kickoff_state_2".to_string(),
                "kickoff_id_2".to_string(),
                owner_type.to_string(),
                true, // dirty
            ),
        ];

        let round_machines = vec![
            (
                "round_state_1".to_string(),
                1,
                owner_type.to_string(),
                true, // dirty
            ),
            (
                "round_state_2".to_string(),
                2,
                owner_type.to_string(),
                true, // dirty
            ),
        ];

        // Save state machines
        db.save_state_machines(None, kickoff_machines.clone(), round_machines.clone(), 123)
            .await
            .unwrap();

        // Check last processed block height
        let block_height = db.get_last_processed_block_height(None).await.unwrap();
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
        assert_eq!(loaded_round[0].1, 1);
        assert_eq!(loaded_round[0].2, 123);

        // Test dirty flag by updating only one machine
        let kickoff_machines_update = vec![
            (
                "kickoff_state_1_updated".to_string(),
                "kickoff_id_1".to_string(),
                owner_type.to_string(),
                true, // dirty - will be updated
            ),
            (
                "kickoff_state_2".to_string(),
                "kickoff_id_2".to_string(),
                owner_type.to_string(),
                false, // not dirty - won't be updated
            ),
        ];

        db.save_state_machines(None, kickoff_machines_update, vec![], 124)
            .await
            .unwrap();

        // Load kickoff machines again to verify only one was updated
        let loaded_kickoff = db.load_kickoff_machines(None, owner_type).await.unwrap();
        assert_eq!(loaded_kickoff.len(), 2);

        // Find the machine with kickoff_id_1 - it should be updated
        let machine1 = loaded_kickoff
            .iter()
            .find(|m| m.1 == "kickoff_id_1")
            .unwrap();
        assert_eq!(machine1.0, "kickoff_state_1_updated");

        // Find the machine with kickoff_id_2 - it should not be updated
        let machine2 = loaded_kickoff
            .iter()
            .find(|m| m.1 == "kickoff_id_2")
            .unwrap();
        assert_eq!(machine2.0, "kickoff_state_2");
    }
}
