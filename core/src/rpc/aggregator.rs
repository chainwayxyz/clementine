use super::clementine::{
    clementine_aggregator_server::ClementineAggregator, DepositParams, Empty, RawSignedMoveTx,
};
use crate::{
    aggregator::Aggregator,
    musig2::aggregate_nonces,
    rpc::clementine::{self, nonce_gen_response, DepositSignSession},
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
        deposit_params: Request<DepositParams>,
    ) -> Result<Response<RawSignedMoveTx>, Status> {
        tracing::info!("Recieved deposit: {:?}", deposit_params);
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

        // Get the first responses from each stream
        let first_responses = try_join_all(nonce_streams.iter_mut().map(|s| async {
            let nonce = s.message().await?;
            let pub_nonce_response = nonce
                .ok_or(Status::internal("No nonce received"))?
                .response
                .ok_or(Status::internal("No nonce received"))?;
            // this response is an enum, so we need to match on it
            match pub_nonce_response {
                nonce_gen_response::Response::FirstResponse(nonce_gen_first_response) => {
                    Ok::<_, Box<dyn std::error::Error + Send + Sync>>(nonce_gen_first_response)
                }
                _ => panic!("Expected FirstResponse"),
            }
        }))
        .await
        .map_err(|e| {
            Status::internal(format!("Failed to get first nonce gen responses {:?}", e))
        })?;

        let num_required_nonces = first_responses[0].num_nonces as usize; // TODO: This should be the same for all verifiers

        // Open the streams for deposit_sign for each verifier
        let mut partial_sig_streams = try_join_all(self.verifier_clients.iter().map(|v| {
            let mut client = v.clone(); // Clone each client to avoid mutable borrow
                                        // https://github.com/hyperium/tonic/issues/33#issuecomment-538150828
            async move {
                let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
                let receiver_stream = tokio_stream::wrappers::UnboundedReceiverStream::new(rx);

                let stream = client.deposit_sign(receiver_stream).await?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>((stream.into_inner(), tx))
                // Return the stream
            }
        }))
        .await
        .map_err(|e| Status::internal(format!("Failed to generate partial sig streams: {:?}", e)))?;

        // Send the first deposit params to each verifier
        let deposit_sign_session = DepositSignSession {
            deposit_params: Some(deposit_params.into_inner()),
            nonce_gen_first_responses: vec![],
        };

        for (_, tx) in partial_sig_streams.iter_mut() {
            tx.send(clementine::VerifierDepositSignParams {
                params: Some(
                    clementine::verifier_deposit_sign_params::Params::DepositSignFirstParam(
                        deposit_sign_session.clone(),
                    ),
                ),
            })
            .unwrap();
        }

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

            tracing::debug!("RECEIVED PUB NONCES: {:?}", pub_nonces);

            // Aggregate the nonces
            let agg_nonce = aggregate_nonces(pub_nonces);

            let agg_nonce_wrapped = clementine::VerifierDepositSignParams {
                params: Some(clementine::verifier_deposit_sign_params::Params::AggNonce(
                    agg_nonce.0.to_vec(),
                )),
            };

            // Send the aggregated nonce to each verifier
            for (_, tx) in partial_sig_streams.iter_mut() {
                tx.send(agg_nonce_wrapped.clone()).unwrap();
            }

            // Get the partial signatures from each verifier
            let partial_sigs = try_join_all(partial_sig_streams.iter_mut().map(|(s, _)| async {
                let partial_sig = s.message().await?;
                let partial_sig = partial_sig.ok_or(Status::internal("No partial sig received"))?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(partial_sig)
            }))
            .await
            .map_err(|e| Status::internal(format!("Failed to get partial sig: {:?}", e)))?;

            println!("Partial sigs: {:?}", partial_sigs);
        }

        Ok(Response::new(RawSignedMoveTx { raw_tx: vec![1, 2] }))
    }
}
