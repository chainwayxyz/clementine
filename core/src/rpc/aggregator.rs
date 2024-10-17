use super::clementine::{
    clementine_aggregator_server::ClementineAggregator, DepositParams, Empty, RawSignedMoveTx,
};
use crate::aggregator::Aggregator;
use tonic::{async_trait, Request, Response, Status};

#[async_trait]
impl ClementineAggregator for Aggregator {
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn setup(&self, _request: Request<Empty>) -> Result<Response<Empty>, Status> {
        todo!()
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn new_deposit(
        &self,
        _request: Request<DepositParams>,
    ) -> Result<Response<RawSignedMoveTx>, Status> {
        todo!()
    }
}
