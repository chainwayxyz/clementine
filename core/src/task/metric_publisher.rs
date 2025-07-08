use std::sync::LazyLock;

use tonic::async_trait;

use crate::metrics::L1SyncStatusProvider;

use crate::{
    database::Database,
    errors::BridgeError,
    extended_rpc::ExtendedRpc,
    metrics::L1_SYNC_STATUS,
    task::{Task, TaskVariant},
    utils::NamedEntity,
};

#[derive(Debug, Clone)]
pub struct MetricPublisher<T: NamedEntity> {
    db: Database,
    rpc: ExtendedRpc,
    _phantom: std::marker::PhantomData<T>,
}

impl<T: NamedEntity> MetricPublisher<T> {
    pub fn new(db: Database, rpc: ExtendedRpc) -> Self {
        Self {
            db,
            rpc,
            _phantom: std::marker::PhantomData,
        }
    }
}

#[async_trait]
impl<T: NamedEntity> Task for MetricPublisher<T> {
    const VARIANT: TaskVariant = TaskVariant::MetricPublisher;
    type Output = bool;

    async fn run_once(&mut self) -> Result<Self::Output, BridgeError> {
        let l1_status = T::get_l1_status(&self.db, &self.rpc).await?;

        let metric = LazyLock::force(&L1_SYNC_STATUS);

        metric
            .wallet_balance_btc
            .set(l1_status.wallet_balance.to_btc());
        metric.rpc_tip_height.set(l1_status.rpc_tip_height as f64);
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

        Ok(true)
    }
}
