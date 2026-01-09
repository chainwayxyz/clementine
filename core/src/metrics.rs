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
use tokio::time::error::Elapsed;
use tonic::async_trait;

use crate::{
    database::Database,
    extended_bitcoin_rpc::ExtendedBitcoinRpc,
    utils::{timed_request_base, NamedEntity},
};
use clementine_errors::BridgeError;
use metrics_derive::Metrics;

const L1_SYNC_STATUS_SUB_REQUEST_METRICS_TIMEOUT: Duration = Duration::from_secs(45);

#[derive(Metrics)]
#[metrics(scope = "l1_sync_status")]
/// The sync status metrics for the currently running entity. (operator/verifier)
pub struct SyncStatusMetrics {
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
    #[metric(describe = "The current Bitcoin fee rate in sat/vB")]
    pub bitcoin_fee_rate_sat_vb: Gauge,
    #[metric(describe = "The current Citrea L2 block height")]
    pub citrea_l2_block_height: Gauge,
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
pub struct EntitySyncStatusMetrics {
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

    #[metric(describe = "The current Bitcoin fee rate in sat/vB for the entity")]
    pub bitcoin_fee_rate_sat_vb: Gauge,
    #[metric(describe = "The current Citrea L2 block height for the entity")]
    pub citrea_l2_block_height: Gauge,

    #[metric(describe = "The number of error responses from the entity status endpoint")]
    pub entity_status_error_count: metrics::Counter,

    #[metric(describe = "The number of stopped tasks for the entity")]
    pub stopped_tasks_count: Gauge,
}

/// The L1 sync status metrics static for the currently running entity. (operator/verifier)
pub static ENTITY_SYNC_STATUS: LazyLock<SyncStatusMetrics> = LazyLock::new(|| {
    SyncStatusMetrics::describe();
    SyncStatusMetrics::default()
});

/// A struct containing the current sync status of the entity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncStatus {
    pub wallet_balance: Option<Amount>,
    pub rpc_tip_height: Option<u32>,
    pub btc_syncer_synced_height: Option<u32>,
    pub hcp_last_proven_height: Option<u32>,
    pub tx_sender_synced_height: Option<u32>,
    pub finalized_synced_height: Option<u32>,
    pub state_manager_next_height: Option<u32>,
    pub bitcoin_fee_rate_sat_vb: Option<u64>,
    pub citrea_l2_block_height: Option<u32>,
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

/// Get the current Bitcoin fee rate in sat/vB.
pub async fn get_bitcoin_fee_rate(
    rpc: &ExtendedBitcoinRpc,
    config: &crate::config::BridgeConfig,
) -> Result<u64, BridgeError> {
    let fee_rate = rpc
        .get_fee_rate(
            config.protocol_paramset.network,
            &config.mempool_api_host,
            &config.mempool_api_endpoint,
            config.tx_sender_limits.mempool_fee_rate_multiplier,
            config.tx_sender_limits.mempool_fee_rate_offset_sat_kvb,
            config.tx_sender_limits.fee_rate_hard_cap,
        )
        .await
        .wrap_err("Failed to get fee rate")?;

    // Convert from FeeRate to sat/vB
    Ok(fee_rate.to_sat_per_vb_ceil())
}

#[async_trait]
/// Extension trait on named entities who synchronize to the L1 data, to retrieve their L1 sync status.
pub trait SyncStatusProvider: NamedEntity {
    async fn get_sync_status<C: crate::citrea::CitreaClientT>(
        db: &Database,
        rpc: &ExtendedBitcoinRpc,
        config: &crate::config::BridgeConfig,
        citrea_client: &C,
    ) -> Result<SyncStatus, BridgeError>;
}

#[inline(always)]
fn log_errs_and_ok<A, T: NamedEntity>(
    result: Result<Result<A, BridgeError>, Elapsed>,
    action: &str,
) -> Option<A> {
    result
        .inspect_err(|_| {
            tracing::error!(
                "[L1SyncStatus({})] Timed out while {action}",
                T::ENTITY_NAME
            )
        })
        .ok()
        .transpose()
        .inspect_err(|e| {
            tracing::error!("[L1SyncStatus({})] Error {action}: {:?}", T::ENTITY_NAME, e)
        })
        .ok()
        .flatten()
}

#[async_trait]
impl<T: NamedEntity> SyncStatusProvider for T {
    async fn get_sync_status<C: crate::citrea::CitreaClientT>(
        db: &Database,
        rpc: &ExtendedBitcoinRpc,
        config: &crate::config::BridgeConfig,
        citrea_client: &C,
    ) -> Result<SyncStatus, BridgeError> {
        let wallet_balance = log_errs_and_ok::<_, T>(
            timed_request_base(
                L1_SYNC_STATUS_SUB_REQUEST_METRICS_TIMEOUT,
                "get_wallet_balance",
                get_wallet_balance(rpc),
            )
            .await,
            "getting wallet balance",
        );

        let rpc_tip_height = log_errs_and_ok::<_, T>(
            timed_request_base(
                L1_SYNC_STATUS_SUB_REQUEST_METRICS_TIMEOUT,
                "get_rpc_tip_height",
                get_rpc_tip_height(rpc),
            )
            .await,
            "getting rpc tip height",
        );

        let tx_sender_synced_height = log_errs_and_ok::<_, T>(
            timed_request_base(
                L1_SYNC_STATUS_SUB_REQUEST_METRICS_TIMEOUT,
                "get_tx_sender_synced_height",
                get_btc_syncer_consumer_last_processed_block_height(db, T::TX_SENDER_CONSUMER_ID),
            )
            .await,
            "getting tx sender synced height",
        )
        .flatten();

        #[cfg(feature = "automation")]
        let finalized_synced_height = log_errs_and_ok::<_, T>(
            timed_request_base(
                L1_SYNC_STATUS_SUB_REQUEST_METRICS_TIMEOUT,
                "get_finalized_synced_height",
                get_btc_syncer_consumer_last_processed_block_height(
                    db,
                    T::FINALIZED_BLOCK_CONSUMER_ID_AUTOMATION,
                ),
            )
            .await,
            "getting finalized synced height",
        )
        .flatten();

        #[cfg(not(feature = "automation"))]
        let finalized_synced_height = log_errs_and_ok::<_, T>(
            timed_request_base(
                L1_SYNC_STATUS_SUB_REQUEST_METRICS_TIMEOUT,
                "get_finalized_synced_height",
                get_btc_syncer_consumer_last_processed_block_height(
                    db,
                    T::FINALIZED_BLOCK_CONSUMER_ID_NO_AUTOMATION,
                ),
            )
            .await,
            "getting finalized synced height",
        )
        .flatten();

        let btc_syncer_synced_height = log_errs_and_ok::<_, T>(
            timed_request_base(
                L1_SYNC_STATUS_SUB_REQUEST_METRICS_TIMEOUT,
                "get_btc_syncer_synced_height",
                get_btc_syncer_synced_height(db),
            )
            .await,
            "getting btc syncer synced height",
        )
        .flatten();

        let hcp_last_proven_height = log_errs_and_ok::<_, T>(
            timed_request_base(
                L1_SYNC_STATUS_SUB_REQUEST_METRICS_TIMEOUT,
                "get_hcp_last_proven_height",
                get_hcp_last_proven_height(db),
            )
            .await,
            "getting hcp last proven height",
        )
        .flatten();
        let state_manager_next_height = log_errs_and_ok::<_, T>(
            timed_request_base(
                L1_SYNC_STATUS_SUB_REQUEST_METRICS_TIMEOUT,
                "get_state_manager_next_height",
                get_state_manager_next_height(db, T::ENTITY_NAME),
            )
            .await,
            "getting state manager next height",
        )
        .flatten();

        let bitcoin_fee_rate_sat_vb = log_errs_and_ok::<_, T>(
            timed_request_base(
                L1_SYNC_STATUS_SUB_REQUEST_METRICS_TIMEOUT,
                "get_bitcoin_fee_rate",
                get_bitcoin_fee_rate(rpc, config),
            )
            .await,
            "getting bitcoin fee rate",
        );

        let citrea_l2_block_height = log_errs_and_ok::<_, T>(
            timed_request_base(
                L1_SYNC_STATUS_SUB_REQUEST_METRICS_TIMEOUT,
                "get_citrea_l2_block_height",
                citrea_client.get_current_l2_block_height(),
            )
            .await,
            "getting citrea L2 block height",
        );

        Ok(SyncStatus {
            wallet_balance,
            rpc_tip_height,
            btc_syncer_synced_height,
            hcp_last_proven_height,
            tx_sender_synced_height,
            finalized_synced_height,
            state_manager_next_height,
            bitcoin_fee_rate_sat_vb,
            citrea_l2_block_height,
        })
    }
}

#[cfg(test)]
mod tests {
    use bitcoincore_rpc::RpcApi;

    #[cfg(not(feature = "automation"))]
    use crate::rpc::clementine::EntityType;
    use crate::{
        rpc::clementine::{Empty, GetEntityStatusesRequest},
        test::common::{
            citrea::MockCitreaClient, create_actors, create_regtest_rpc,
            create_test_config_with_thread_name,
        },
    };
    use std::time::Duration;

    #[tokio::test]
    async fn test_get_sync_status_should_not_fail() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        config.bitcoin_rpc_url += "/wallet/test-wallet";
        // unload to avoid conflicts
        regtest.rpc().unload_wallet("admin".into()).await.unwrap();

        // create a test wallet
        regtest
            .rpc()
            .create_wallet("test-wallet", None, None, None, None)
            .await
            .unwrap();

        let addr = regtest.rpc().get_new_address(None, None).await.unwrap();
        regtest
            .rpc()
            .generate_to_address(201, addr.assume_checked_ref())
            .await
            .unwrap();

        let actors = create_actors::<MockCitreaClient>(&config).await;

        // lose the wallet that was previously loaded for some reason
        regtest
            .rpc()
            .unload_wallet(Some("test-wallet"))
            .await
            .unwrap();

        // try to get status which includes balance
        let res = actors
            .get_verifier_client_by_index(0)
            .get_current_status(Empty {})
            .await;

        // expect result to be Ok(_)
        assert!(res.is_ok(), "Expected Ok(_) but got {res:?}");

        // expect the balance to be None because the wallet was unloaded
        assert_eq!(res.unwrap().into_inner().wallet_balance, None);
    }

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
                        assert!(
                            status
                                .tx_sender_synced_height
                                .expect("tx_sender_synced_height is None")
                                > 0
                        );
                        assert!(
                            status
                                .finalized_synced_height
                                .expect("finalized_synced_height is None")
                                > 0
                        );
                        assert!(
                            status
                                .hcp_last_proven_height
                                .expect("hcp_last_proven_height is None")
                                > 0
                        );
                        assert!(status.rpc_tip_height.expect("rpc_tip_height is None") > 0);
                        assert!(
                            status
                                .bitcoin_syncer_synced_height
                                .expect("bitcoin_syncer_synced_height is None")
                                > 0
                        );
                        assert!(
                            status
                                .state_manager_next_height
                                .expect("state_manager_next_height is None")
                                > 0
                        );
                        assert!(status.wallet_balance.is_some());
                        assert!(
                            status
                                .btc_fee_rate_sat_vb
                                .expect("btc_fee_rate_sat_vb is None")
                                > 0
                        );
                        assert!(status.citrea_l2_block_height.is_some());
                    }
                    #[cfg(not(feature = "automation"))]
                    {
                        let entity_type: EntityType =
                            entity.entity_id.unwrap().kind.try_into().unwrap();
                        // tx sender and hcp are not running in non-automation mode
                        assert!(!status.automation);
                        assert!(status.tx_sender_synced_height.is_none());
                        if entity_type == EntityType::Verifier {
                            assert!(
                                status
                                    .finalized_synced_height
                                    .expect("finalized_synced_height is None")
                                    > 0
                            );
                        } else {
                            // operator doesn't run finalized block fetcher in non-automation mode
                            assert!(status.finalized_synced_height.is_none());
                        }
                        assert!(status.hcp_last_proven_height.is_none());
                        assert!(status.rpc_tip_height.expect("rpc_tip_height is None") > 0);
                        assert!(
                            status
                                .bitcoin_syncer_synced_height
                                .expect("bitcoin_syncer_synced_height is None")
                                > 0
                        );
                        assert!(status.state_manager_next_height.is_none());
                        assert!(status.wallet_balance.is_some());
                        assert!(
                            status
                                .btc_fee_rate_sat_vb
                                .expect("bitcoin_fee_rate_sat_vb is None")
                                > 0
                        );
                        assert!(status.citrea_l2_block_height.is_some());
                    }
                }
                crate::rpc::clementine::entity_status_with_id::StatusResult::Err(error) => {
                    let error_msg = &error.error;
                    panic!("Couldn't get entity status: {error_msg}");
                }
            }
        }
    }
}
