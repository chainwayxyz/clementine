use std::str::FromStr;
use std::{collections::HashMap, time::Duration};

use tonic::async_trait;

use crate::{
    aggregator::{Aggregator, EntityId, OperatorId, VerifierId},
    metrics::EntitySyncStatusMetrics,
    rpc::clementine::EntityType,
    task::{Task, TaskVariant},
};
use clementine_errors::BridgeError;

pub const AGGREGATOR_METRIC_PUBLISHER_POLL_DELAY: Duration = Duration::from_secs(120);

/// Publishes metrics for the aggregator, including the Entity Statuses of all registered entities.
#[derive(Debug)]
pub struct AggregatorMetricPublisher {
    aggregator: Aggregator,
    metrics: HashMap<EntityId, EntitySyncStatusMetrics>,
}

impl AggregatorMetricPublisher {
    pub async fn new(aggregator: Aggregator) -> Result<Self, BridgeError> {
        Ok(Self {
            aggregator: Aggregator::new(aggregator.config).await?,
            metrics: HashMap::new(),
        })
    }

    /// Convert protobuf EntityId to rust EntityId
    fn convert_entity_id(
        proto_entity_id: &crate::rpc::clementine::EntityId,
    ) -> Result<EntityId, BridgeError> {
        let entity_type = EntityType::try_from(proto_entity_id.kind)
            .map_err(|_| BridgeError::ConfigError("Invalid entity type".into()))?;

        match entity_type {
            EntityType::Operator => {
                let xonly_pk =
                    bitcoin::XOnlyPublicKey::from_str(&proto_entity_id.id).map_err(|e| {
                        BridgeError::ConfigError(format!("Invalid operator xonly public key: {e}"))
                    })?;
                Ok(EntityId::Operator(OperatorId(xonly_pk)))
            }
            EntityType::Verifier => {
                let pk =
                    bitcoin::secp256k1::PublicKey::from_str(&proto_entity_id.id).map_err(|e| {
                        BridgeError::ConfigError(format!("Invalid verifier public key: {e}"))
                    })?;
                Ok(EntityId::Verifier(VerifierId(pk)))
            }
            EntityType::Aggregator => Ok(EntityId::Aggregator),
            EntityType::EntityUnknown => {
                Err(BridgeError::ConfigError("Unknown entity type".into()))
            }
        }
    }

    /// Create or get metrics for an entity
    fn get_or_create_metrics(&mut self, entity_id: EntityId) -> &mut EntitySyncStatusMetrics {
        self.metrics.entry(entity_id).or_insert_with(|| {
            let scope = format!("{entity_id}_l1_sync_status");
            EntitySyncStatusMetrics::describe(&scope);
            EntitySyncStatusMetrics::new(&scope)
        })
    }
}

#[async_trait]
impl Task for AggregatorMetricPublisher {
    const VARIANT: TaskVariant = TaskVariant::MetricPublisher;
    type Output = bool;

    async fn run_once(&mut self) -> Result<Self::Output, BridgeError> {
        // Metrics are not published in tests
        tracing::info!("Publishing metrics for aggregator");

        let entity_statuses = self
            .aggregator
            .get_entity_statuses(false)
            .await
            .inspect_err(|e| {
                tracing::error!("Error getting entities status: {:?}", e);
            })?;

        tracing::info!("Entities status: {:?}", entity_statuses);

        if cfg!(test) {
            return Ok(false);
        }

        // Process each entity status
        for entity_status_with_id in entity_statuses {
            let proto_entity_id = entity_status_with_id
                .entity_id
                .ok_or_else(|| BridgeError::ConfigError("Missing entity_id".into()))?;

            let entity_id = match Self::convert_entity_id(&proto_entity_id) {
                Ok(id) => id,
                Err(e) => {
                    tracing::error!("Failed to convert entity_id: {}", e);
                    continue;
                }
            };

            let metrics = self.get_or_create_metrics(entity_id);

            match entity_status_with_id.status_result {
                Some(crate::rpc::clementine::entity_status_with_id::StatusResult::Status(
                    status,
                )) => {
                    // Parse wallet balance from string (format is "X.XXX BTC")
                    if let Some(balance) = status
                        .wallet_balance
                        .and_then(|s| s.strip_suffix(" BTC").and_then(|s| s.parse::<f64>().ok()))
                    {
                        metrics.wallet_balance_btc.set(balance);
                    }

                    if let Some(height) = status.rpc_tip_height {
                        metrics.rpc_tip_height.set(height as f64);
                    }
                    if let Some(height) = status.bitcoin_syncer_synced_height {
                        metrics.btc_syncer_synced_height.set(height as f64);
                    }
                    if let Some(height) = status.hcp_last_proven_height {
                        metrics.hcp_last_proven_height.set(height as f64);
                    }
                    if let Some(height) = status.tx_sender_synced_height {
                        metrics.tx_sender_synced_height.set(height as f64);
                    }
                    if let Some(height) = status.finalized_synced_height {
                        metrics.finalized_synced_height.set(height as f64);
                    }
                    if let Some(height) = status.state_manager_next_height {
                        metrics.state_manager_next_height.set(height as f64);
                    }
                    if let Some(tasks) = status.stopped_tasks {
                        metrics
                            .stopped_tasks_count
                            .set(tasks.stopped_tasks.len() as f64);
                    }
                    if let Some(fee_rate) = status.btc_fee_rate_sat_vb {
                        metrics.bitcoin_fee_rate_sat_vb.set(fee_rate as f64);
                    }
                    if let Some(height) = status.citrea_l2_block_height {
                        metrics.citrea_l2_block_height.set(height as f64);
                    }
                }
                Some(crate::rpc::clementine::entity_status_with_id::StatusResult::Err(error)) => {
                    tracing::error!("Entity {} error: {}", entity_id, error.error);
                    // Increment error counter
                    metrics.entity_status_error_count.increment(1);
                }
                None => {
                    tracing::warn!("Entity {} has no status", entity_id);
                }
            }
        }

        // Always delay by returning false (ie. no work done)
        Ok(false)
    }
}
