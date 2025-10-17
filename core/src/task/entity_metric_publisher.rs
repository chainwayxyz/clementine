use std::sync::LazyLock;
use std::time::Duration;

use tonic::async_trait;

use crate::metrics::L1SyncStatusProvider;

use crate::{
    database::Database,
    errors::BridgeError,
    extended_bitcoin_rpc::ExtendedBitcoinRpc,
    metrics::L1_SYNC_STATUS,
    task::{Task, TaskVariant},
    utils::NamedEntity,
};

/// The interval at which the entity metrics are polled and published
/// (Not sent to Prometheus at this interval, since we use a pull-based http listener)
///
/// This doubles as the timeout for entity status retrieval.
pub const ENTITY_METRIC_PUBLISHER_INTERVAL: Duration = Duration::from_secs(120);

#[derive(Debug, Clone)]
/// Publishes the metrics available for an entity (operator/verifier)
pub struct EntityMetricPublisher<T: NamedEntity> {
    db: Database,
    rpc: ExtendedBitcoinRpc,
    config: crate::config::BridgeConfig,
    _phantom: std::marker::PhantomData<T>,
}

impl<T: NamedEntity> EntityMetricPublisher<T> {
    pub fn new(db: Database, rpc: ExtendedBitcoinRpc, config: crate::config::BridgeConfig) -> Self {
        Self {
            db,
            rpc,
            config,
            _phantom: std::marker::PhantomData,
        }
    }
}

#[async_trait]
impl<T: NamedEntity> Task for EntityMetricPublisher<T> {
    const VARIANT: TaskVariant = TaskVariant::MetricPublisher;
    type Output = bool;

    async fn run_once(&mut self) -> Result<Self::Output, BridgeError> {
        // Metrics are not published in tests
        if cfg!(test) {
            return Ok(false);
        }

        let l1_status = match T::get_l1_status(&self.db, &self.rpc, &self.config).await {
            Ok(l1_status) => l1_status,
            Err(e) => {
                tracing::error!(
                    "Failed to get l1 status when publishing metrics for {}: {:?}",
                    T::ENTITY_NAME,
                    e
                );

                return Ok(false);
            }
        };

        let metric = LazyLock::force(&L1_SYNC_STATUS);

        metric
            .wallet_balance_btc
            .set(l1_status.wallet_balance.map_or(0.0, |a| a.to_btc()));
        metric
            .rpc_tip_height
            .set(l1_status.rpc_tip_height.unwrap_or(0) as f64);
        metric
            .hcp_last_proven_height
            .set(l1_status.hcp_last_proven_height.unwrap_or(0) as f64);
        metric
            .btc_syncer_synced_height
            .set(l1_status.btc_syncer_synced_height.unwrap_or(0) as f64);
        metric
            .finalized_synced_height
            .set(l1_status.finalized_synced_height.unwrap_or(0) as f64);
        metric
            .tx_sender_synced_height
            .set(l1_status.tx_sender_synced_height.unwrap_or(0) as f64);
        metric
            .state_manager_next_height
            .set(l1_status.state_manager_next_height.unwrap_or(0) as f64);
        metric
            .bitcoin_fee_rate_sat_vb
            .set(l1_status.bitcoin_fee_rate_sat_vb.unwrap_or(0) as f64);

        Ok(false)
    }
}
