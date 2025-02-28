// use crate::{database::Database, test::common::*};

// /// Tests basic saving and loading of state machine data directly from the database
// #[tokio::test]
// async fn test_database_save_and_load_state_machines() {
//     // Create a test configuration and database
//     let config = create_test_config_with_thread_name(None).await;
//     let db = Database::new(&config).await.unwrap();

//     // Create test data
//     let kickoff_machines = vec![
//         (
//             0,
//             "kickoff_state_1".to_string(),
//             Some("kickoff_id_1".to_string()),
//         ),
//         (
//             1,
//             "kickoff_state_2".to_string(),
//             Some("kickoff_id_2".to_string()),
//         ),
//     ];

//     let round_machines = vec![
//         (0, "round_state_1".to_string(), Some(1)),
//         (1, "round_state_2".to_string(), Some(2)),
//     ];

//     // Save state to the database with a specific block height
//     let block_height = 123;
//     let save_result = db
//         .save_state_machines(
//             None,
//             kickoff_machines.clone(),
//             round_machines.clone(),
//             block_height,
//         )
//         .await;
//     assert!(save_result.is_ok(), "Saving state should succeed");

//     // Verify that the last processed block height was saved correctly
//     let db_block_height = db.get_last_processed_block_height(None).await.unwrap();
//     assert_eq!(
//         db_block_height,
//         Some(block_height),
//         "Last processed block height should match"
//     );

//     // Load kickoff machines
//     let loaded_kickoff = db.load_kickoff_machines(None).await.unwrap();
//     assert_eq!(loaded_kickoff.len(), 2, "Should have 2 kickoff machines");
//     assert_eq!(
//         loaded_kickoff[0].0, 0,
//         "First kickoff machine idx should be 0"
//     );
//     assert_eq!(
//         loaded_kickoff[0].1, "kickoff_state_1",
//         "First kickoff machine state should match"
//     );
//     assert_eq!(
//         loaded_kickoff[0].2,
//         Some("kickoff_id_1".to_string()),
//         "First kickoff machine ID should match"
//     );
//     assert_eq!(
//         loaded_kickoff[0].3, block_height,
//         "First kickoff machine block height should match"
//     );

//     // Load round machines
//     let loaded_round = db.load_round_machines(None).await.unwrap();
//     assert_eq!(loaded_round.len(), 2, "Should have 2 round machines");
//     assert_eq!(loaded_round[0].0, 0, "First round machine idx should be 0");
//     assert_eq!(
//         loaded_round[0].1, "round_state_1",
//         "First round machine state should match"
//     );
//     assert_eq!(
//         loaded_round[0].2,
//         Some(1),
//         "First round machine operator idx should match"
//     );
//     assert_eq!(
//         loaded_round[0].3, block_height,
//         "First round machine block height should match"
//     );
// }

// #[tokio::test]
// async fn test_transaction_isolation() {
//     // Create a test configuration and database with a unique name
//     let config = create_test_config_with_thread_name(Some("transaction_isolation")).await;
//     let db = Database::new(&config).await.unwrap();

//     // Save initial state with a specific block height
//     let initial_block_height = 789;
//     db.save_state_machines(None, Vec::new(), Vec::new(), initial_block_height)
//         .await
//         .unwrap();

//     // Start a transaction but don't commit it
//     let mut tx = db.begin_transaction().await.unwrap();

//     // Update state in the transaction
//     let transaction_block_height = 999;
//     db.save_state_machines(
//         Some(&mut tx),
//         Vec::new(),
//         Vec::new(),
//         transaction_block_height,
//     )
//     .await
//     .unwrap();

//     // Verify that within the transaction we see the updated state
//     let tx_block_height = db
//         .get_last_processed_block_height(Some(&mut tx))
//         .await
//         .unwrap();
//     assert_eq!(
//         tx_block_height,
//         Some(transaction_block_height),
//         "Within the transaction, block height should match transaction block height"
//     );

//     // But outside the transaction we still see the old value
//     let global_block_height = db.get_last_processed_block_height(None).await.unwrap();
//     assert_eq!(
//         global_block_height,
//         Some(initial_block_height),
//         "Outside the transaction, block height should remain unchanged"
//     );

//     // Roll back the transaction
//     tx.rollback().await.unwrap();

//     // Verify that the global state is unchanged
//     let final_block_height = db.get_last_processed_block_height(None).await.unwrap();
//     assert_eq!(
//         final_block_height,
//         Some(initial_block_height),
//         "After rollback, block height should remain unchanged"
//     );
// }
