use bitcoin::{consensus, Block};

use super::common::{create_test_config_with_thread_name, initialize_database, MockOwner};
use crate::{config::BridgeConfig, database::Database, states::StateManager};

// Helper function to create a test state manager
async fn create_test_state_manager(
    config: &BridgeConfig,
) -> (StateManager<MockOwner>, BridgeConfig) {
    let db = Database::new(config)
        .await
        .expect("Failed to create database");
    let owner = Default::default();

    let state_manager = StateManager::new(db, owner, config.protocol_paramset())
        .await
        .unwrap();

    (state_manager, config.clone())
}

async fn create_test_config() -> BridgeConfig {
    let config = create_test_config_with_thread_name().await;
    initialize_database(&config).await;
    config
}

// Helper function to create an empty block for testing
fn create_empty_block() -> Block {
    // from bitcoin tests
    let some_block = hex::decode("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b0201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804ffff001d026e04ffffffff0100f2052a0100000043410446ef0102d1ec5240f0d061a4246c1bdef63fc3dbab7733052fbbf0ecd8f41fc26bf049ebb4f9527f374280259e7cfa99c48b0e3f39c51347a19a5819651503a5ac00000000010000000321f75f3139a013f50f315b23b0c9a2b6eac31e2bec98e5891c924664889942260000000049483045022100cb2c6b346a978ab8c61b18b5e9397755cbd17d6eb2fe0083ef32e067fa6c785a02206ce44e613f31d9a6b0517e46f3db1576e9812cc98d159bfdaf759a5014081b5c01ffffffff79cda0945903627c3da1f85fc95d0b8ee3e76ae0cfdc9a65d09744b1f8fc85430000000049483045022047957cdd957cfd0becd642f6b84d82f49b6cb4c51a91f49246908af7c3cfdf4a022100e96b46621f1bffcf5ea5982f88cef651e9354f5791602369bf5a82a6cd61a62501fffffffffe09f5fe3ffbf5ee97a54eb5e5069e9da6b4856ee86fc52938c2f979b0f38e82000000004847304402204165be9a4cbab8049e1af9723b96199bfd3e85f44c6b4c0177e3962686b26073022028f638da23fc003760861ad481ead4099312c60030d4cb57820ce4d33812a5ce01ffffffff01009d966b01000000434104ea1feff861b51fe3f5f8a3b12d0f4712db80e919548a80839fc47c6a21e66d957e9c5d8cd108c7a2d2324bad71f9904ac0ae7336507d785b17a2c115e427a32fac00000000").unwrap();

    consensus::deserialize(&some_block).unwrap()
}

#[tokio::test]
async fn test_process_empty_block_with_no_machines() {
    let (mut state_manager, _config) = create_test_state_manager(&create_test_config().await).await;

    let block = create_empty_block();
    let block_height = 1;

    state_manager.update_block_cache(&block, block_height);
    // Process an empty block with no state machines
    let result = state_manager.process_block_parallel(block_height).await;

    // Should succeed with no state changes
    assert!(
        result.is_ok(),
        "Failed to process empty block: {:?}",
        result
    );
}

#[tokio::test]
async fn test_process_block_parallel() {
    let (mut state_manager, _config) = create_test_state_manager(&create_test_config().await).await;

    // Create a block
    let block = create_empty_block();

    // Process the block multiple times to test the iteration logic
    for i in 1..=3 {
        state_manager.update_block_cache(&block, i);
        let result = state_manager.process_block_parallel(i).await;
        assert!(
            result.is_ok(),
            "Failed to process block on iteration {}: {:?}",
            i,
            result
        );
    }
}

#[tokio::test]
async fn test_save_and_load_state() {
    let (mut state_manager, config) = create_test_state_manager(&create_test_config().await).await;

    // Process a block to ensure the state is initialized
    let block = create_empty_block();
    state_manager.update_block_cache(&block, 1);
    let result = state_manager.process_block_parallel(1).await;
    assert!(result.is_ok(), "Failed to process block: {:?}", result);

    // Save state to DB
    let result = state_manager.save_state_to_db(1).await;
    assert!(result.is_ok(), "Failed to save state to DB: {:?}", result);

    // Create a new state manager to load from DB
    let (mut new_state_manager, _) = create_test_state_manager(&config).await;

    // Load state from DB
    let result = new_state_manager.load_from_db().await;
    assert!(result.is_ok(), "Failed to load state from DB: {:?}", result);

    // Check that the state is the same
    let mut round_machines = new_state_manager.round_machines();
    let mut kickoff_machines = new_state_manager.kickoff_machines();

    round_machines.sort_by_key(|m| m.operator_data.xonly_pk);
    kickoff_machines.sort_by_key(|m| m.kickoff_data);

    let mut round_machines_old = state_manager.round_machines();
    let mut kickoff_machines_old = state_manager.kickoff_machines();

    round_machines_old.sort_by_key(|m| m.operator_data.xonly_pk);
    kickoff_machines_old.sort_by_key(|m| m.kickoff_data);

    assert_eq!(round_machines, round_machines_old);
    assert_eq!(kickoff_machines, kickoff_machines_old);
}
