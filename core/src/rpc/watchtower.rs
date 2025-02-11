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
        let (watchtower_id, winternitz_public_keys, xonly_pk) = self.get_params().await?;

        let (tx, rx) = mpsc::channel(winternitz_public_keys.len() + 2);
        let out_stream: Self::GetParamsStream = ReceiverStream::new(rx);

        tracing::info!(
            "Watchtower gives watchtower xonly public key {:?} for index {}",
            self.actor.xonly_public_key,
            self.config.index
        );

        tokio::spawn(async move {
            tx.send(Ok(WatchtowerParams {
                response: Some(watchtower_params::Response::WatchtowerId(watchtower_id)),
            }))
            .await?;

            for wpk in winternitz_public_keys {
                let wpk: WatchtowerParams = wpk.into();
                tx.send(Ok(wpk)).await?;
            }

            let xonly_pk: WatchtowerParams = xonly_pk.into();
            tx.send(Ok(xonly_pk)).await?;

            Ok::<(), SendError<_>>(())
        });

        Ok(Response::new(out_stream))
    }
}
