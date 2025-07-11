use std::str::FromStr;
use std::{collections::HashMap, time::Duration};

use tonic::{async_trait, Request};

use crate::{
    aggregator::{Aggregator, EntityId, OperatorId, VerifierId},
    errors::BridgeError,
    metrics::EntityL1SyncStatusMetrics,
    rpc::clementine::{
        clementine_aggregator_server::ClementineAggregator as _, EntityType,
        GetEntitiesStatusRequest,
    },
    task::{Task, TaskVariant},
};

pub const AGGREGATOR_METRIC_PUBLISHER_POLL_DELAY: Duration = Duration::from_secs(60);

/// Publishes metrics for the aggregator, including the Entity Statuses of all registered entities.
#[derive(Debug)]
pub struct AggregatorMetricPublisher {
    aggregator: Aggregator,
    metrics: HashMap<EntityId, EntityL1SyncStatusMetrics>,
}

impl AggregatorMetricPublisher {
    pub fn new(aggregator: Aggregator) -> Self {
        Self {
            aggregator,
            metrics: HashMap::new(),
        }
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
                        BridgeError::ConfigError(format!(
                            "Invalid operator xonly public key: {}",
                            e
                        ))
                    })?;
                Ok(EntityId::Operator(OperatorId(xonly_pk)))
            }
            EntityType::Verifier => {
                let pk =
                    bitcoin::secp256k1::PublicKey::from_str(&proto_entity_id.id).map_err(|e| {
                        BridgeError::ConfigError(format!("Invalid verifier public key: {}", e))
                    })?;
                Ok(EntityId::Verifier(VerifierId(pk)))
            }
            EntityType::EntityUnknown => {
                Err(BridgeError::ConfigError("Unknown entity type".into()))
            }
        }
    }

    /// Create or get metrics for an entity
    fn get_or_create_metrics(&mut self, entity_id: EntityId) -> &mut EntityL1SyncStatusMetrics {
        self.metrics.entry(entity_id).or_insert_with(|| {
            let scope = format!("{}_l1_sync_status", entity_id);
            EntityL1SyncStatusMetrics::new(&scope)
        })
    }
}

#[async_trait]
impl Task for AggregatorMetricPublisher {
    const VARIANT: TaskVariant = TaskVariant::MetricPublisher;
    type Output = bool;

    async fn run_once(&mut self) -> Result<Self::Output, BridgeError> {
        // Metrics are not published in tests
        if cfg!(test) {
            return Ok(false);
        }

        let entities_status = self
            .aggregator
            .get_entities_status(Request::new(GetEntitiesStatusRequest {
                restart_tasks: false,
            }))
            .await?
            .into_inner();

        // Process each entity status
        for entity_status_with_id in entities_status.entities_status {
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

            match entity_status_with_id.status {
                Some(crate::rpc::clementine::entity_status_with_id::Status::EntityStatus(
                    status,
                )) => {
                    // Parse wallet balance from string (format is "X.XXX BTC")
                    let wallet_balance_btc = status
                        .wallet_balance
                        .strip_suffix(" BTC")
                        .and_then(|s| s.parse::<f64>().ok())
                        .unwrap_or(0.0);

                    // Update all metrics
                    metrics.wallet_balance_btc.set(wallet_balance_btc);
                    metrics.rpc_tip_height.set(status.rpc_tip_height as f64);
                    metrics
                        .btc_syncer_synced_height
                        .set(status.bitcoin_syncer_synced_height as f64);
                    metrics
                        .hcp_last_proven_height
                        .set(status.hcp_last_proven_height as f64);
                    metrics
                        .tx_sender_synced_height
                        .set(status.tx_sender_synced_height as f64);
                    metrics
                        .finalized_synced_height
                        .set(status.finalized_synced_height as f64);
                    metrics
                        .state_manager_next_height
                        .set(status.state_manager_next_height as f64);
                }
                Some(crate::rpc::clementine::entity_status_with_id::Status::EntityError(error)) => {
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
