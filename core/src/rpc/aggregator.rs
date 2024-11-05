use super::clementine::{
    clementine_aggregator_server::ClementineAggregator, DepositParams, Empty, RawSignedMoveTx,
};
use crate::{
    actor::Actor,
    aggregator::Aggregator,
    builder,
    musig2::aggregate_nonces,
    rpc::clementine::{self, nonce_gen_response, DepositSignSession, NonceGenResponse},
    ByteArray32, ByteArray66, EVMAddress,
};
use bitcoin::hashes::Hash;
use bitcoin::Amount;
use futures::{future::try_join_all, FutureExt};
use tonic::{async_trait, Request, Response, Status, Streaming};

#[async_trait]
impl ClementineAggregator for Aggregator {
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn setup(&self, _request: Request<Empty>) -> Result<Response<Empty>, Status> {
        todo!()
    }

    // #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn new_deposit(
        &self,
        deposit_params_req: Request<DepositParams>,
    ) -> Result<Response<RawSignedMoveTx>, Status> {
        tracing::info!("Recieved new deposit request: {:?}", deposit_params_req);

        let deposit_params = deposit_params_req.into_inner();

        let deposit_outpoint: bitcoin::OutPoint = deposit_params
            .clone()
            .deposit_outpoint
            .ok_or(Status::internal("No deposit outpoint received"))
            .unwrap()
            .try_into()
            .unwrap();
        let evm_address: EVMAddress = deposit_params.clone().evm_address.try_into().unwrap();
        let recovery_taproot_address = deposit_params
            .clone()
            .recovery_taproot_address
            .parse::<bitcoin::Address<_>>()
            .unwrap();
        let user_takes_after = deposit_params.clone().user_takes_after;
        let nofn_xonly_pk = self.nofn_xonly_pk.clone();
        let verifiers_public_keys = self.config.verifiers_public_keys.clone();

        tracing::debug!("Parsed deposit params");

        // generate nonces from all verifiers
        let mut nonce_streams = try_join_all(self.verifier_clients.iter().map(|client| {
            // Clone each client to avoid mutable borrow.
            // https://github.com/hyperium/tonic/issues/33#issuecomment-538150828
            let mut client = client.clone();

            async move {
                let response_stream = client.nonce_gen(Request::new(Empty {})).await?;

                Ok::<_, Status>(response_stream.into_inner())
            }
        }))
        .await?;

        tracing::debug!("Generated nonce streams");

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
                    Ok::<_, Status>(nonce_gen_first_response)
                }
                _ => panic!("Expected FirstResponse"),
            }
        }))
        .await
        .map_err(|e| {
            Status::internal(format!("Failed to get first nonce gen responses {:?}", e))
        })?;

        tracing::debug!("Received first responses: {:?}", first_responses);

        let num_required_nonces = first_responses[0].num_nonces as usize; // TODO: This should be the same for all verifiers

        // Open the streams for deposit_sign for each verifier
        let mut partial_sig_streams = try_join_all(self.verifier_clients.iter().map(|v| {
            let mut client = v.clone(); // Clone each client to avoid mutable borrow
                                        // https://github.com/hyperium/tonic/issues/33#issuecomment-538150828
            async move {
                let (tx, rx) = tokio::sync::mpsc::channel(128);
                let receiver_stream = tokio_stream::wrappers::ReceiverStream::new(rx);
                // let x = tokio_stream::iter(1..usize::MAX).map(|i| i.to_string());
                let stream = client.deposit_sign(receiver_stream).await?;
                Ok::<_, Status>((stream.into_inner(), tx))
                // Return the stream
            }
        }))
        .await
        .map_err(|e| {
            Status::internal(format!("Failed to generate partial sig streams: {:?}", e))
        })?;

        tracing::debug!("Generated partial sig streams");

        // Send the first deposit params to each verifier
        let deposit_sign_session = DepositSignSession {
            deposit_params: Some(deposit_params),
            nonce_gen_first_responses: first_responses,
        };

        tracing::debug!("Sent deposit sign session");

        for (_, tx) in partial_sig_streams.iter_mut() {
            tx.send(clementine::VerifierDepositSignParams {
                params: Some(
                    clementine::verifier_deposit_sign_params::Params::DepositSignFirstParam(
                        deposit_sign_session.clone(),
                    ),
                ),
            })
            .await
            .unwrap();
        }

        let mut deposit_finalize_clients = self.verifier_clients.clone();
        // Open the streams for deposit_finalize
        let deposit_finalize_streams =
            try_join_all(deposit_finalize_clients.iter_mut().map(|v| {
                async move {
                    let (tx, rx) = tokio::sync::mpsc::channel(128);
                    let receiver_stream = tokio_stream::wrappers::ReceiverStream::new(rx);

                    // Move `client` into this async block and use it directly
                    let deposit_finalize_futures = v.deposit_finalize(receiver_stream).boxed();

                    Ok::<_, Status>((deposit_finalize_futures, tx))
                }
            }))
            .await
            .map_err(|e| {
                Status::internal(format!("Failed to generate partial sig streams: {:?}", e))
            })?;
        let (mut deposit_finalize_futures, deposit_finalize_sender): (Vec<_>, Vec<_>) =
            deposit_finalize_streams.into_iter().unzip();

        let deposit_finalize_first_param = clementine::VerifierDepositFinalizeParams {
            params: Some(clementine::verifier_deposit_finalize_params::Params::DepositSignFirstParam(
                deposit_sign_session.clone(),
            )),
        };

        for tx in deposit_finalize_sender.iter() {
            tx.send(deposit_finalize_first_param.clone()).await.unwrap();
        }

        for nonce_idx in 0..num_required_nonces {
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
                tx.send(agg_nonce_wrapped.clone()).await.unwrap();
            }

            // Get the partial signatures from each verifier
            let partial_sigs = try_join_all(partial_sig_streams.iter_mut().map(|(s, _)| async {
                let partial_sig = s.message().await?;
                let partial_sig = partial_sig.ok_or(Status::internal("No partial sig received"))?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(ByteArray32(
                    partial_sig.partial_sig.try_into().unwrap(),
                ))
            }))
            .await
            .map_err(|e| Status::internal(format!("Failed to get partial sig: {:?}", e)))?;

            println!("Partial sigs: {:?}", partial_sigs);

            let mut dummy_move_tx_handler = builder::transaction::create_move_tx_handler(
                deposit_outpoint,
                evm_address,
                &recovery_taproot_address,
                nofn_xonly_pk,
                bitcoin::Network::Regtest,
                user_takes_after as u32,
                Amount::from_sat(nonce_idx as u64 + 1000000),
            );

            let move_tx_sighash = ByteArray32(
                Actor::convert_tx_to_sighash_script_spend(&mut dummy_move_tx_handler, 0, 0)
                    .unwrap()
                    .to_byte_array(),
            );

            tracing::debug!("Aggregator found sighash: {:?}", move_tx_sighash);

            let final_sig = crate::musig2::aggregate_partial_signatures(
                verifiers_public_keys.clone(),
                None,
                false,
                &agg_nonce,
                partial_sigs,
                move_tx_sighash,
            )
            .unwrap();

            tracing::debug!("Final signature: {:?}", final_sig);

            for tx in deposit_finalize_sender.iter() {
                tx.send(clementine::VerifierDepositFinalizeParams {
                    params: Some(
                        clementine::verifier_deposit_finalize_params::Params::SchnorrSig(
                            final_sig.to_vec(),
                        ),
                    ),
                })
                .await
                .unwrap();
            }
        }

        // for (future, _) in deposit_finalize_streams.iter_mut() {
        //     let x = future;
        //     let x = future.await.unwrap();
        // }

        tracing::debug!("Waiting for deposit finalization");

        let move_tx_partial_sigs = try_join_all(
            deposit_finalize_futures
                .iter_mut()
                .map(|f| async { Ok::<_, Status>(f.await.unwrap().into_inner().partial_sig) }),
        )
        .await
        .map_err(|e| Status::internal(format!("Failed to finalize deposit: {:?}", e)))?;

        tracing::debug!("Received move tx partial sigs: {:?}", move_tx_partial_sigs);

        Ok(Response::new(RawSignedMoveTx { raw_tx: vec![1, 2] }))
    }
}
