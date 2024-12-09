use super::clementine::{
    clementine_watchtower_server::ClementineWatchtower, Empty, WatchtowerParams,
};
use crate::watchtower::Watchtower;
use tonic::{async_trait, Request, Response, Status};

#[async_trait]
impl ClementineWatchtower for Watchtower {
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    #[allow(clippy::blocks_in_conditions)]
    async fn get_params(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<WatchtowerParams>, Status> {
        // let sig = self.actor.derive_winternitz_pk(path);
        todo!()
    }
}
