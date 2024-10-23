use super::clementine::{
    clementine_aggregator_server::ClementineAggregator, DepositParams, Empty, RawSignedMoveTx,
};
use crate::{
    aggregator::Aggregator,
    musig2::{aggregate_nonces, MuSigPubNonce},
    rpc::clementine::nonce_gen_response,
    ByteArray66,
};
use futures::future::try_join_all;
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
        tracing::info!("Recieved deposit: {:?}", _request);
        // generate nonces from all verifiers
        let mut nonce_streams = try_join_all(self.verifier_clients.iter().map(|v| {
            let mut client = v.clone(); // Clone each client to avoid mutable borrow
                                        // https://github.com/hyperium/tonic/issues/33#issuecomment-538150828
            async move {
                let stream = client.nonce_gen(Request::new(Empty {})).await?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(stream.into_inner())
                // Return the stream
            }
        }))
        .await
        .map_err(|e| Status::internal(format!("Failed to generate nonce streams: {:?}", e)))?;

        let num_required_nonces = 10;

        for _ in 0..num_required_nonces {
            // Get the next nonce from each stream
            let pub_nonces = try_join_all(nonce_streams.iter_mut().map(|s| async {
                let nonce = s.message().await?;
                let pub_nonce_response = nonce
                    .ok_or(Status::internal("No nonce received"))?
                    .response
                    .ok_or(Status::internal("No nonce received"))?;
                // this response is an enum, so we need to match on it
                match pub_nonce_response {
                    nonce_gen_response::Response::PubNonce(pub_nonce) => {
                        let musig2_pub_nonce: [u8; 66] = pub_nonce.try_into().unwrap();
                        let pub_nonce = ByteArray66(musig2_pub_nonce);
                        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(pub_nonce)
                    }
                    _ => panic!("Expected PubNonce"),
                }
            }))
            .await
            .map_err(|e| Status::internal(format!("Failed to get nonce: {:?}", e)))?;

            // Aggregate the nonces
            let agg_nonce = aggregate_nonces(pub_nonces);

            tracing::info!("Aggregated nonce: {:?}", agg_nonce);
        }

        Ok(Response::new(RawSignedMoveTx { raw_tx: vec![1, 2] }))
    }
}
