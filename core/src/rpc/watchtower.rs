use super::clementine::{
    clementine_watchtower_server::ClementineWatchtower, Empty, WatchtowerParams,
};
use crate::watchtower::Watchtower;
use bitcoin_mock_rpc::RpcApiWrapper;
use tonic::{async_trait, Request, Response, Status};

#[async_trait]
impl<T> ClementineWatchtower for Watchtower<T>
where
    T: RpcApiWrapper,
{
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn get_params(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<WatchtowerParams>, Status> {
        todo!()
    }
}
