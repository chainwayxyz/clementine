//! This module includes helper functions to get the blockchain synchronization status of the entity.
//! The entity tracks on-chain transactions for many purposes (TxSender,
//! FinalizedBlockFetcher, HCP) and takes action (header chain proving, payout,
//! disprove, L2 state sync, etc.)
//! SyncStatus tracks the latest processed block heights for each of these tasks.
//!
use std::{sync::LazyLock, time::Duration};

use bitcoin::Amount;
use bitcoincore_rpc::RpcApi;
use eyre::Context;
use metrics::Gauge;
use tonic::async_trait;

use crate::{
    database::Database,
    errors::BridgeError,
    extended_bitcoin_rpc::ExtendedBitcoinRpc,
    utils::{timed_request, NamedEntity},
};
use metrics_derive::Metrics;

const L1_SYNC_STATUS_METRICS_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Metrics)]
#[metrics(scope = "l1_sync_status")]
/// The L1 sync status metrics for the currently running entity. (operator/verifier)
pub struct L1SyncStatusMetrics {
    #[metric(describe = "The current balance of the wallet in Bitcoin (BTC)")]
    pub wallet_balance_btc: Gauge,
    #[metric(describe = "The block height of the chain as seen by Bitcoin Core RPC")]
    pub rpc_tip_height: Gauge,
    #[metric(describe = "The block height of the Bitcoin Syncer")]
    pub btc_syncer_synced_height: Gauge,
    #[metric(describe = "The block height of the latest header chain proof")]
    pub hcp_last_proven_height: Gauge,
    #[metric(describe = "The block height processed by the Transaction Sender")]
    pub tx_sender_synced_height: Gauge,
    #[metric(describe = "The finalized block height as seen by the FinalizedBlockFetcher task")]
    pub finalized_synced_height: Gauge,
    #[metric(describe = "The next block height to process for the State Manager")]
    pub state_manager_next_height: Gauge,
}

#[derive(Metrics)]
#[metrics(dynamic = true)]
/// The L1 sync status metrics for an entity. This is used by the aggregator to
/// publish external entity metrics.  The scope will be set to the EntityId +
/// "_l1_sync_status", which will be displayed as
/// `Operator(abcdef123...)_l1_sync_status` or
/// `Verifier(abcdef123...)_l1_sync_status` where the XOnlyPublicKey's first 10
/// characters are displayed, cf. [`crate::aggregator::OperatorId`] and
/// [`crate::aggregator::VerifierId`].
pub struct EntityL1SyncStatusMetrics {
    #[metric(describe = "The current balance of the wallet of the entity in Bitcoin (BTC)")]
    pub wallet_balance_btc: Gauge,
    #[metric(
        describe = "The block height of the chain as seen by Bitcoin Core RPC for the entity"
    )]
    pub rpc_tip_height: Gauge,
    #[metric(describe = "The block height of the Bitcoin Syncer for the entity")]
    pub btc_syncer_synced_height: Gauge,
    #[metric(describe = "The block height of the latest header chain proof for the entity")]
    pub hcp_last_proven_height: Gauge,
    #[metric(describe = "The block height processed by the Transaction Sender for the entity")]
    pub tx_sender_synced_height: Gauge,
    #[metric(
        describe = "The finalized block height as seen by the FinalizedBlockFetcher task for the entity"
    )]
    pub finalized_synced_height: Gauge,
    #[metric(describe = "The next block height to process for the State Manager for the entity")]
    pub state_manager_next_height: Gauge,

    #[metric(describe = "The number of error responses from the entity status endpoint")]
    pub entity_status_error_count: metrics::Counter,

    #[metric(describe = "The number of stopped tasks for the entity")]
    pub stopped_tasks_count: Gauge,
}

/// The L1 sync status metrics static for the currently running entity. (operator/verifier)
pub static L1_SYNC_STATUS: LazyLock<L1SyncStatusMetrics> = LazyLock::new(|| {
    L1SyncStatusMetrics::describe();
    L1SyncStatusMetrics::default()
});

/// A struct containing the current sync status of the entity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L1SyncStatus {
    pub wallet_balance: Amount,
    pub rpc_tip_height: u32,
    pub btc_syncer_synced_height: Option<u32>,
    pub hcp_last_proven_height: Option<u32>,
    pub tx_sender_synced_height: Option<u32>,
    pub finalized_synced_height: Option<u32>,
    pub state_manager_next_height: Option<u32>,
}

/// Get the current balance of the wallet.
pub async fn get_wallet_balance(rpc: &ExtendedBitcoinRpc) -> Result<Amount, BridgeError> {
    let balance = rpc
        .get_balance(None, None)
        .await
        .wrap_err("Failed to get wallet balance")?;

    Ok(balance)
}

/// Get the current height of the chain as seen by Bitcoin Core RPC.
pub async fn get_rpc_tip_height(rpc: &ExtendedBitcoinRpc) -> Result<u32, BridgeError> {
    let height = rpc.get_current_chain_height().await?;
    Ok(height)
}

/// Get the last processed block height of the given consumer or None if no
/// block was processed by the consumer.
pub async fn get_btc_syncer_consumer_last_processed_block_height(
    db: &Database,
    consumer_handle: &str,
) -> Result<Option<u32>, BridgeError> {
    db.get_last_processed_event_block_height(None, consumer_handle)
        .await
}

/// Get the last processed block height of the Bitcoin Syncer or None if no
/// block is present in the database.
pub async fn get_btc_syncer_synced_height(db: &Database) -> Result<Option<u32>, BridgeError> {
    let height = db.get_max_height(None).await?;
    Ok(height)
}

/// Get the last proven block height of the HCP or None if no block has been proven.
pub async fn get_hcp_last_proven_height(db: &Database) -> Result<Option<u32>, BridgeError> {
    let latest_proven_block_height = db
        .get_latest_proven_block_info(None)
        .await?
        .map(|(_, _, height)| height as u32);
    Ok(latest_proven_block_height)
}

/// Get the next height of the State Manager or None if the State Manager status
/// for the owner is missing or the next_height_to_process is NULL.
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

#[async_trait]
/// Extension trait on named entities who synchronize to the L1 data, to retrieve their L1 sync status.
pub trait L1SyncStatusProvider: NamedEntity {
    async fn get_l1_status(
        db: &Database,
        rpc: &ExtendedBitcoinRpc,
    ) -> Result<L1SyncStatus, BridgeError>;
}

#[async_trait]
impl<T: NamedEntity + Sync + Send + 'static> L1SyncStatusProvider for T {
    async fn get_l1_status(
        db: &Database,
        rpc: &ExtendedBitcoinRpc,
    ) -> Result<L1SyncStatus, BridgeError> {
        timed_request(L1_SYNC_STATUS_METRICS_TIMEOUT, "get_l1_status", async {
            let wallet_balance = get_wallet_balance(rpc).await?;
            let rpc_tip_height = get_rpc_tip_height(rpc).await?;
            let tx_sender_synced_height =
                get_btc_syncer_consumer_last_processed_block_height(db, T::TX_SENDER_CONSUMER_ID)
                    .await?;
            let finalized_synced_height = get_btc_syncer_consumer_last_processed_block_height(
                db,
                T::FINALIZED_BLOCK_CONSUMER_ID,
            )
            .await?;
            let btc_syncer_synced_height = get_btc_syncer_synced_height(db).await?;
            let hcp_last_proven_height = get_hcp_last_proven_height(db).await?;
            let state_manager_next_height =
                get_state_manager_next_height(db, T::ENTITY_NAME).await?;

            Ok(L1SyncStatus {
                wallet_balance,
                rpc_tip_height,
                btc_syncer_synced_height,
                hcp_last_proven_height,
                tx_sender_synced_height,
                finalized_synced_height,
                state_manager_next_height,
            })
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "automation"))]
    use crate::rpc::clementine::EntityType;
    use crate::{
        rpc::clementine::GetEntityStatusesRequest,
        test::common::{
            citrea::MockCitreaClient, create_actors, create_regtest_rpc,
            create_test_config_with_thread_name,
        },
    };
    use std::time::Duration;

    #[tokio::test]
    async fn test_get_sync_status() {
        let mut config = create_test_config_with_thread_name().await;
        let _regtest = create_regtest_rpc(&mut config).await;
        let actors = create_actors::<MockCitreaClient>(&config).await;
        let mut aggregator = actors.get_aggregator();
        // wait for entities to sync a bit, this might cause flakiness, if so increase sleep time or make it serial
        tokio::time::sleep(Duration::from_secs(40)).await;
        let entity_statuses = aggregator
            .get_entity_statuses(tonic::Request::new(GetEntityStatusesRequest {
                restart_tasks: false,
            }))
            .await
            .unwrap()
            .into_inner();

        for entity in entity_statuses.entity_statuses {
            let status = entity.status_result.unwrap();
            match status {
                crate::rpc::clementine::entity_status_with_id::StatusResult::Status(status) => {
                    tracing::info!("Status: {:#?}", status);
                    #[cfg(feature = "automation")]
                    {
                        assert!(status.automation);
                        assert!(status.tx_sender_synced_height > 0);
                        assert!(status.finalized_synced_height > 0);
                        assert!(status.hcp_last_proven_height > 0);
                        assert!(status.rpc_tip_height > 0);
                        assert!(status.bitcoin_syncer_synced_height > 0);
                        assert!(status.state_manager_next_height > 0);
                    }
                    #[cfg(not(feature = "automation"))]
                    {
                        let entity_type: EntityType =
                            entity.entity_id.unwrap().kind.try_into().unwrap();
                        // tx sender and hcp are not running in non-automation mode
                        assert!(!status.automation);
                        assert!(status.tx_sender_synced_height == 0);
                        if entity_type == EntityType::Verifier {
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
                crate::rpc::clementine::entity_status_with_id::StatusResult::Err(error) => {
                    panic!("Coudln't get entity status: {}", error.error);
                }
            }
        }
    }
}
