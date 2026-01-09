use std::sync::LazyLock;
use std::time::Duration;

use tonic::async_trait;

use crate::metrics::SyncStatusProvider;

use crate::{
    citrea::CitreaClientT,
    database::Database,
    extended_bitcoin_rpc::ExtendedBitcoinRpc,
    metrics::ENTITY_SYNC_STATUS,
    task::{Task, TaskVariant},
    utils::NamedEntity,
};
use clementine_errors::BridgeError;

/// The interval at which the entity metrics are polled and published
/// (Not sent to Prometheus at this interval, since we use a pull-based http listener)
///
/// This doubles as the timeout for entity status retrieval.
pub const ENTITY_METRIC_PUBLISHER_INTERVAL: Duration = Duration::from_secs(120);

#[derive(Debug, Clone)]
/// Publishes the metrics available for an entity (operator/verifier)
pub struct EntityMetricPublisher<T: NamedEntity, C: CitreaClientT> {
    db: Database,
    rpc: ExtendedBitcoinRpc,
    config: crate::config::BridgeConfig,
    citrea_client: C,
    _phantom: std::marker::PhantomData<T>,
}

impl<T: NamedEntity, C: CitreaClientT> EntityMetricPublisher<T, C> {
    pub fn new(
        db: Database,
        rpc: ExtendedBitcoinRpc,
        config: crate::config::BridgeConfig,
        citrea_client: C,
    ) -> Self {
        Self {
            db,
            rpc,
            config,
            citrea_client,
            _phantom: std::marker::PhantomData,
        }
    }
}

#[async_trait]
impl<T: NamedEntity, C: CitreaClientT> Task for EntityMetricPublisher<T, C> {
    const VARIANT: TaskVariant = TaskVariant::MetricPublisher;
    type Output = bool;

    async fn run_once(&mut self) -> Result<Self::Output, BridgeError> {
        // Metrics are not published in tests
        if cfg!(test) {
            return Ok(false);
        }

        let sync_status = match T::get_sync_status(
            &self.db,
            &self.rpc,
            &self.config,
            &self.citrea_client,
        )
        .await
        {
            Ok(sync_status) => sync_status,
            Err(e) => {
                tracing::error!(
                    "Failed to get l1 status when publishing metrics for {}: {:?}",
                    T::ENTITY_NAME,
                    e
                );

                return Ok(false);
            }
        };

        let metric = LazyLock::force(&ENTITY_SYNC_STATUS);

        if let Some(balance) = sync_status.wallet_balance {
            metric.wallet_balance_btc.set(balance.to_btc());
        }
        if let Some(height) = sync_status.rpc_tip_height {
            metric.rpc_tip_height.set(height as f64);
        }
        if let Some(height) = sync_status.hcp_last_proven_height {
            metric.hcp_last_proven_height.set(height as f64);
        }
        if let Some(height) = sync_status.btc_syncer_synced_height {
            metric.btc_syncer_synced_height.set(height as f64);
        }
        if let Some(height) = sync_status.finalized_synced_height {
            metric.finalized_synced_height.set(height as f64);
        }
        if let Some(height) = sync_status.tx_sender_synced_height {
            metric.tx_sender_synced_height.set(height as f64);
        }
        if let Some(height) = sync_status.state_manager_next_height {
            metric.state_manager_next_height.set(height as f64);
        }
        if let Some(fee_rate) = sync_status.bitcoin_fee_rate_sat_vb {
            metric.bitcoin_fee_rate_sat_vb.set(fee_rate as f64);
        }
        if let Some(height) = sync_status.citrea_l2_block_height {
            metric.citrea_l2_block_height.set(height as f64);
        }

        Ok(false)
    }
}
