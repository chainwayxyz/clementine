//! This module includes helper functions to get the current status of the entity.
use bitcoincore_rpc::RpcApi;
use eyre::Context;

use crate::{
    database::Database, errors::BridgeError, extended_rpc::ExtendedRpc, utils::NamedEntity,
};

/// A struct containing the current sync status of the entity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncStatus {
    pub wallet_balance: String,
    pub rpc_tip_height: u32,
    pub btc_syncer_synced_height: Option<u32>,
    pub hcp_last_proven_height: Option<u32>,
    pub tx_sender_synced_height: Option<u32>,
    pub finalized_synced_height: Option<u32>,
    pub state_manager_next_height: Option<u32>,
}

/// Get the current balance of the wallet.
pub async fn get_wallet_balance(rpc: &ExtendedRpc) -> Result<String, BridgeError> {
    let balance = rpc
        .client
        .get_balance(None, None)
        .await
        .wrap_err("Failed to get wallet balance")?;
    Ok(format!("{} btc", balance.to_btc()))
}

/// Get the current height of the chain as seen by Bitcoin Core RPC.
pub async fn get_rpc_tip_height(rpc: &ExtendedRpc) -> Result<u32, BridgeError> {
    let height = rpc.get_current_chain_height().await?;
    Ok(height)
}

/// Get the last processed block height of the given consumer.
pub async fn get_btc_syncer_consumer_last_processed_block_height(
    db: &Database,
    consumer_handle: &str,
) -> Result<Option<u32>, BridgeError> {
    let mut dbtx = db.begin_transaction().await?;
    let height = db
        .get_last_processed_event_block_height(&mut dbtx, consumer_handle)
        .await?;
    dbtx.commit().await?;
    Ok(height)
}

/// Get the last processed block height of the Bitcoin Syncer.
pub async fn get_btc_syncer_synced_height(db: &Database) -> Result<Option<u32>, BridgeError> {
    let height = db.get_max_height(None).await?;
    Ok(height)
}

/// Get the last proven block height of the HCP.
pub async fn get_hcp_last_proven_height(db: &Database) -> Result<Option<u32>, BridgeError> {
    let latest_proven_block_height = db
        .get_latest_proven_block_info(None)
        .await?
        .map(|(_, _, height)| height as u32);
    Ok(latest_proven_block_height)
}

/// Get the next height of the State Manager.
pub async fn get_state_manager_next_height(
    db: &Database,
    owner_type: &str,
) -> Result<Option<u32>, BridgeError> {
    #[cfg(feature = "automation")]
    {
        let next_height = db
            .get_next_height_to_process(None, owner_type)
            .await?
            .map(|x| x as u32);
        Ok(next_height)
    }
    #[cfg(not(feature = "automation"))]
    {
        Ok(None)
    }
}

/// Get full sync status of the entity.
pub async fn get_sync_status<T: NamedEntity>(
    db: &Database,
    rpc: &ExtendedRpc,
) -> Result<SyncStatus, BridgeError> {
    let wallet_balance = get_wallet_balance(rpc).await?;
    let rpc_tip_height = get_rpc_tip_height(rpc).await?;
    let tx_sender_synced_height =
        get_btc_syncer_consumer_last_processed_block_height(db, T::TX_SENDER_CONSUMER_ID).await?;
    let finalized_synced_height =
        get_btc_syncer_consumer_last_processed_block_height(db, T::FINALIZED_BLOCK_CONSUMER_ID)
            .await?;
    let btc_syncer_synced_height = get_btc_syncer_synced_height(db).await?;
    let hcp_last_proven_height = get_hcp_last_proven_height(db).await?;
    let state_manager_next_height = get_state_manager_next_height(db, T::ENTITY_NAME).await?;

    Ok(SyncStatus {
        wallet_balance,
        rpc_tip_height,
        btc_syncer_synced_height,
        hcp_last_proven_height,
        tx_sender_synced_height,
        finalized_synced_height,
        state_manager_next_height,
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::{
        rpc::clementine::{Entities, GetEntitiesStatusRequest},
        test::common::{
            citrea::MockCitreaClient, create_actors, create_regtest_rpc,
            create_test_config_with_thread_name,
        },
    };

    use super::*;

    #[tokio::test]
    async fn test_get_sync_status() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc();
        let (_, _, mut aggregator, _cleanup) = create_actors::<MockCitreaClient>(&config).await;
        // wait for entities to sync a bit, this might cause flakiness, if so increase sleep time or make it serial
        tokio::time::sleep(Duration::from_secs(40)).await;
        let entities_status = aggregator
            .get_entities_status(tonic::Request::new(GetEntitiesStatusRequest {
                restart_tasks: false,
            }))
            .await
            .unwrap()
            .into_inner();

        for entity in entities_status.entities_status {
            let status = entity.status.unwrap();
            let entity_type = Entities::from_i32(entity.entity_id.unwrap().entity).unwrap();
            match status {
                crate::rpc::clementine::entity_status_with_id::Status::EntityStatus(status) => {
                    tracing::info!("Status: {:#?}", status);
                    #[cfg(feature = "automation")]
                    {
                        assert!(status.automation == true);
                        assert!(status.tx_sender_synced_height > 0);
                        assert!(status.finalized_synced_height > 0);
                        assert!(status.hcp_last_proven_height > 0);
                        assert!(status.rpc_tip_height > 0);
                        assert!(status.bitcoin_syncer_synced_height > 0);
                        assert!(status.state_manager_next_height > 0);
                    }
                    #[cfg(not(feature = "automation"))]
                    {
                        // tx sender and hcp are not running in non-automation mode
                        assert!(status.automation == false);
                        assert!(status.tx_sender_synced_height == 0);
                        if entity_type == Entities::Verifier {
                            assert!(status.finalized_synced_height > 0);
                        } else {
                            // operator doesn't run finalized block fetcher in non-automation mode
                            assert!(status.finalized_synced_height == 0);
                        }
                        assert!(status.hcp_last_proven_height == 0);
                        assert!(status.rpc_tip_height > 0);
                        assert!(status.bitcoin_syncer_synced_height > 0);
                        assert!(status.state_manager_next_height == 0);
                    }
                }
                crate::rpc::clementine::entity_status_with_id::Status::EntityError(error) => {
                    panic!("Coudln't get entity status: {}", error.error);
                }
            }
        }
    }
}
