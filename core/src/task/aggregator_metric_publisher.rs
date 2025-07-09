use std::collections::HashMap;

use tonic::{async_trait, Request};

use crate::{
    aggregator::{Aggregator, EntityId},
    errors::BridgeError,
    metrics::EntityL1SyncStatusMetrics,
    rpc::clementine::{
        clementine_aggregator_server::ClementineAggregator as _, GetEntitiesStatusRequest,
    },
    task::{Task, TaskVariant},
};

/// Publishes metrics for the aggregator, including the Entity Statuses of all registered entities.
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
}

#[async_trait]
impl Task for AggregatorMetricPublisher {
    const VARIANT: TaskVariant = TaskVariant::MetricPublisher;
    type Output = bool;

    async fn run_once(&mut self) -> Result<Self::Output, BridgeError> {
        let entities_status = self
            .aggregator
            .get_entities_status(Request::new(GetEntitiesStatusRequest {
                restart_tasks: false,
            }))
            .await?
            .into_inner();

        // Always delay by returning false (ie. no work done)
        Ok(false)
    }
}
