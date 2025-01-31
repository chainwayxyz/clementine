use super::clementine::{
    clementine_watchtower_server::ClementineWatchtower, watchtower_params, Empty, WatchtowerParams,
    WinternitzPubkey,
};
use crate::watchtower::Watchtower;
use tokio::sync::mpsc::{self, error::SendError};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{async_trait, Request, Response, Status};

#[async_trait]
impl ClementineWatchtower for Watchtower {
    type GetParamsStream = ReceiverStream<Result<WatchtowerParams, Status>>;

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    #[allow(clippy::blocks_in_conditions)]
    async fn get_params(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<Self::GetParamsStream>, Status> {
        let winternitz_pubkeys = self
            .get_watchtower_winternitz_public_keys()
            .await?
            .into_iter()
            .map(From::from)
            .collect::<Vec<WinternitzPubkey>>();
        let watchtower = self.clone();

        let (tx, rx) = mpsc::channel(1280);
        tokio::spawn(async move {
            tx.send(Ok(WatchtowerParams {
                response: Some(watchtower_params::Response::WatchtowerId(
                    watchtower.config.index,
                )),
            }))
            .await?;

            for wpk in winternitz_pubkeys {
                tx.send(Ok(WatchtowerParams {
                    response: Some(watchtower_params::Response::WinternitzPubkeys(wpk)),
                }))
                .await?;
            }

            tracing::info!(
                "Watchtower gives watchtower xonly public key: {:?}",
                watchtower.actor.xonly_public_key
            );
            tracing::info!(
                "Watchtower gives watchtower index: {:?}",
                watchtower.config.index
            );
            let xonly_pk = watchtower.actor.xonly_public_key.serialize().to_vec();

            tracing::info!(
                "Watchtower gives watchtower xonly public key bytes: {:?}",
                xonly_pk
            );

            tx.send(Ok(WatchtowerParams {
                response: Some(watchtower_params::Response::XonlyPk(xonly_pk)),
            }))
            .await?;

            Ok::<(), SendError<_>>(())
        });

        let out_stream: Self::GetParamsStream = ReceiverStream::new(rx);
        Ok(Response::new(out_stream))
    }
}
