use super::clementine::{
    clementine_watchtower_server::ClementineWatchtower, watchtower_params, DepositParams, Empty,
    RawSignedTx, TransactionRequest, WatchtowerKeys, WatchtowerParams,
};
use crate::constants::WATCHTOWER_CHALLENGE_MESSAGE_LENGTH;
use crate::rpc::parser::{parse_deposit_params, parse_transaction_request};
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
        let (watchtower_id, xonly_pk) = self.get_params().await?;

        let (tx, rx) = mpsc::channel(3);
        let out_stream: Self::GetParamsStream = ReceiverStream::new(rx);

        tracing::info!(
            "Watchtower gives watchtower xonly public key {:?} for index {}",
            self.signer.xonly_public_key,
            self.config.index
        );

        tokio::spawn(async move {
            tx.send(Ok(WatchtowerParams {
                response: Some(watchtower_params::Response::WatchtowerId(watchtower_id)),
            }))
            .await?;

            let xonly_pk: WatchtowerParams = xonly_pk.into();
            tx.send(Ok(xonly_pk)).await?;

            Ok::<(), SendError<_>>(())
        });

        Ok(Response::new(out_stream))
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn internal_create_watchtower_challenge(
        &self,
        request: Request<TransactionRequest>,
    ) -> Result<Response<RawSignedTx>, Status> {
        let transaction_request = request.into_inner();
        let transaction_data = parse_transaction_request(transaction_request)?;

        let raw_tx = self
            .create_and_sign_watchtower_challenge(
                self.nofn_xonly_pk,
                transaction_data,
                &vec![
                    0u8;
                    self.config
                        .protocol_paramset()
                        .watchtower_challenge_message_length
                        / 2
                ], // dummy challenge
            )
            .await?;

        Ok(Response::new(raw_tx))
    }

    async fn get_challenge_keys(
        &self,
        request: Request<DepositParams>,
    ) -> Result<Response<WatchtowerKeys>, Status> {
        let deposit_req = request.into_inner();
        let deposit_data = parse_deposit_params(deposit_req)?;

        let winternitz_keys =
            self.get_watchtower_winternitz_public_keys(deposit_data.deposit_outpoint.txid)?;

        Ok(Response::new(WatchtowerKeys {
            winternitz_pubkeys: winternitz_keys
                .into_iter()
                .map(|pubkey| pubkey.into())
                .collect(),
        }))
    }
}
