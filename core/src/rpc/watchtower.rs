use super::clementine::{
    clementine_watchtower_server::ClementineWatchtower, watchtower_params, Empty, WatchtowerParams,
};
use crate::watchtower::Watchtower;
use tokio::sync::mpsc::{self, error::SendError};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{async_trait, Request, Response, Status};

#[async_trait]
impl ClementineWatchtower for Watchtower {
    type GetParamsStream = ReceiverStream<Result<WatchtowerParams, Status>>;

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn get_params(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<Self::GetParamsStream>, Status> {
        let watchtower = self.clone();
        let watchtower_winternitz_public_keys =
            watchtower.get_watchtower_winternitz_public_keys().await?;

        let (tx, rx) = mpsc::channel(watchtower_winternitz_public_keys.len() + 2);
        let out_stream: Self::GetParamsStream = ReceiverStream::new(rx);

        tokio::spawn(async move {
            tx.send(Ok(WatchtowerParams {
                response: Some(watchtower_params::Response::WatchtowerId(
                    watchtower.config.index,
                )),
            }))
            .await?;

            for wpk in watchtower_winternitz_public_keys {
                let wpk: WatchtowerParams = wpk.into();
                tx.send(Ok(wpk)).await?;
            }

            tracing::info!(
                "Watchtower gives watchtower xonly public key {:?} for index {}",
                watchtower.actor.xonly_public_key,
                watchtower.config.index
            );

            let xonly_pk: WatchtowerParams = watchtower.actor.xonly_public_key.into();
            tx.send(Ok(xonly_pk)).await?;

            Ok::<(), SendError<_>>(())
        });

        Ok(Response::new(out_stream))
    }
}
