use super::clementine::{
    clementine_aggregator_server::ClementineAggregator, DepositParams, Empty, RawSignedMoveTx,
};
use crate::{
    aggregator::Aggregator,
    builder::sighash::{calculate_num_required_sigs, create_nofn_sighash_stream},
    errors::BridgeError,
    musig2::{aggregate_nonces, MuSigPubNonce},
    rpc::clementine::{self, DepositSignSession},
    ByteArray32, ByteArray66, EVMAddress,
};
use bitcoin::{hashes::Hash, Amount};
use futures::{future::try_join_all, stream::BoxStream, FutureExt, StreamExt};
use std::pin::pin;
use tonic::{async_trait, Request, Response, Status};

impl Aggregator {
    // Extracts pub_nonce from given stream.
    fn extract_pub_nonce(
        response: Option<clementine::nonce_gen_response::Response>,
    ) -> Result<ByteArray66, BridgeError> {
        match response
            .ok_or_else(|| BridgeError::Error("NonceGen response is empty".to_string()))?
        {
            clementine::nonce_gen_response::Response::PubNonce(pub_nonce) => pub_nonce
                .try_into()
                .map(ByteArray66)
                .map_err(|_| BridgeError::Error("PubNonce should be exactly 66 bytes".to_string())),
            _ => Err(BridgeError::Error(
                "Expected PubNonce in response".to_string(),
            )),
        }
    }

    /// Creates a stream of nonces from verifiers.
    /// This will automatically get's the first response from the verifiers.
    ///
    /// # Returns
    ///
    /// - Vec<[`clementine::NonceGenFirstResponse`]>: First response from each verifier
    /// - Vec<BoxStream<Result<[`MuSigPubNonce`], BridgeError>>>: Stream of nonces from each verifier
    async fn create_nonce_streams(
        &self,
        num_nonces: u32,
    ) -> Result<
        (
            Vec<clementine::NonceGenFirstResponse>,
            Vec<BoxStream<Result<MuSigPubNonce, BridgeError>>>,
        ),
        BridgeError,
    > {
        // Generate nonces from all verifiers.
        let mut nonce_streams = try_join_all(self.verifier_clients.iter().map(|client| {
            let mut client = client.clone();
            async move {
                let response_stream = client
                    .nonce_gen(tonic::Request::new(clementine::NonceGenRequest {
                        num_nonces,
                    }))
                    .await?;

                Ok::<_, Status>(response_stream.into_inner())
            }
        }))
        .await?;

        // Get the first responses from each stream.
        let first_responses: Vec<clementine::NonceGenFirstResponse> =
            try_join_all(nonce_streams.iter_mut().map(|s| async {
                let nonce_gen_first_response = s
                    .message()
                    .await?
                    .ok_or(BridgeError::Error("NonceGen returns nothing".to_string()))?
                    .response
                    .ok_or(BridgeError::Error(
                        "NonceGen response field is empty".to_string(),
                    ))?;

                if let clementine::nonce_gen_response::Response::FirstResponse(
                    nonce_gen_first_response,
                ) = nonce_gen_first_response
                {
                    Ok(nonce_gen_first_response)
                } else {
                    Err(BridgeError::Error(
                        "NonceGen response is not FirstResponse".to_string(),
                    ))
                }
            }))
            .await?;

        let transformed_streams: Vec<BoxStream<Result<ByteArray66, BridgeError>>> = nonce_streams
            .into_iter()
            .map(|stream| {
                stream
                    .map(|result| Self::extract_pub_nonce(result?.response))
                    .boxed()
            })
            .collect();

        Ok((first_responses, transformed_streams))
    }
}

#[async_trait]
impl ClementineAggregator for Aggregator {
    #[tracing::instrument(skip_all, err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn setup(&self, _request: Request<Empty>) -> Result<Response<Empty>, Status> {
        tracing::info!("Collecting verifier details...");
        let verifier_params = try_join_all(self.verifier_clients.iter().map(|client| {
            let mut client = client.clone();
            async move {
                let response = client.get_params(Request::new(Empty {})).await?;
                Ok::<_, Status>(response.into_inner())
            }
        }))
        .await?;
        let verifier_public_keys: Vec<Vec<u8>> =
            verifier_params.into_iter().map(|p| p.public_key).collect();
        tracing::debug!("Verifier public keys: {:?}", verifier_public_keys);

        tracing::info!("Setting up verifiers...");
        try_join_all(self.verifier_clients.iter().map(|client| {
            let mut client = client.clone();
            {
                let verifier_public_keys = clementine::VerifierPublicKeys {
                    verifier_public_keys: verifier_public_keys.clone(),
                };
                async move {
                    let response = client
                        .set_verifiers(Request::new(verifier_public_keys))
                        .await?;
                    Ok::<_, Status>(response.into_inner())
                }
            }
        }))
        .await?;

        tracing::info!("Collecting operator details...");
        let operator_params = try_join_all(self.operator_clients.iter().map(|client| {
            let mut client = client.clone();
            async move {
                let response = client.get_params(Request::new(Empty {})).await?;
                Ok::<_, Status>(response.into_inner())
            }
        }))
        .await?;

        tracing::info!("Informing verifiers for existing operators...");
        try_join_all(self.verifier_clients.iter().map(|client| {
            let mut client = client.clone();
            let params = operator_params.clone();

            async move {
                for param in params {
                    client.set_operator(Request::new(param)).await?;
                }

                Ok::<_, tonic::Status>(())
            }
        }))
        .await?;

        tracing::info!("Collecting Winternitz public keys from watchtowers...");
        let watchtower_params = try_join_all(self.watchtower_clients.iter().map(|client| {
            let mut client = client.clone();
            async move {
                let response = client.get_params(Request::new(Empty {})).await?;
                Ok::<_, Status>(response.into_inner())
            }
        }))
        .await?;

        tracing::info!("Sending Winternitz public keys to verifiers...");
        try_join_all(self.verifier_clients.iter().map(|client| {
            let mut client = client.clone();
            let params = watchtower_params.clone();

            async move {
                for param in params {
                    client.set_watchtower(Request::new(param)).await.unwrap();
                }

                Ok::<_, tonic::Status>(())
            }
        }))
        .await?;

        Ok(Response::new(Empty {}))
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn new_deposit(
        &self,
        deposit_params_req: Request<DepositParams>,
    ) -> Result<Response<RawSignedMoveTx>, Status> {
        let deposit_params = deposit_params_req.into_inner();

        let deposit_outpoint: bitcoin::OutPoint = deposit_params
            .clone()
            .deposit_outpoint
            .ok_or(Status::internal("No deposit outpoint received"))?
            .try_into()?;
        let evm_address: EVMAddress = deposit_params.clone().evm_address.try_into().unwrap();
        let recovery_taproot_address = deposit_params
            .clone()
            .recovery_taproot_address
            .parse::<bitcoin::Address<_>>()
            .unwrap();
        let user_takes_after = deposit_params.clone().user_takes_after;
        let verifiers_public_keys = self.config.verifiers_public_keys.clone();

        tracing::debug!("Parsed deposit params");

        // generate nonces from all verifiers
        let num_required_sigs = calculate_num_required_sigs(
            self.config.num_operators,
            self.config.num_time_txs,
            self.config.num_watchtowers,
        );
        let (first_responses, mut nonce_streams) =
            self.create_nonce_streams(num_required_sigs as u32).await?;

        // Open the streams for deposit_sign for each verifier
        let mut partial_sig_streams = try_join_all(self.verifier_clients.iter().map(|v| {
            let mut client = v.clone(); // Clone each client to avoid mutable borrow
                                        // https://github.com/hyperium/tonic/issues/33#issuecomment-538150828
            async move {
                let (tx, rx) = tokio::sync::mpsc::channel(1280);
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
        let deposit_finalize_streams = try_join_all(deposit_finalize_clients.iter_mut().map(|v| {
            async move {
                let (tx, rx) = tokio::sync::mpsc::channel(1280);
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
            params: Some(
                clementine::verifier_deposit_finalize_params::Params::DepositSignFirstParam(
                    deposit_sign_session.clone(),
                ),
            ),
        };

        for tx in deposit_finalize_sender.iter() {
            tx.send(deposit_finalize_first_param.clone()).await.unwrap();
        }

        let mut sighash_stream = pin!(create_nofn_sighash_stream(
            self.db.clone(),
            self.config.clone(),
            deposit_outpoint,
            evm_address,
            recovery_taproot_address,
            self.nofn_xonly_pk,
            user_takes_after,
            Amount::from_sat(200_000_000), // TODO: Fix this.
            6,
            100,
            self.config.bridge_amount_sats,
            self.config.network,
        ));

        let num_required_sigs = calculate_num_required_sigs(
            self.config.num_operators,
            self.config.num_time_txs,
            self.config.num_watchtowers,
        );

        for _ in 0..num_required_sigs {
            // Get the next nonce from each stream
            let pub_nonces = try_join_all(nonce_streams.iter_mut().map(|s| async {
                s.next()
                    .await
                    .ok_or_else(|| Status::internal("Stream ended unexpectedly"))? // Handle if stream ends early
                    .map_err(|e| Status::internal(format!("Failed to get nonce: {:?}", e)))
                // Handle if there's an error in the stream item
            }))
            .await?;

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

            tracing::trace!("Received partial sigs: {:?}", partial_sigs);

            let sighash = sighash_stream.next().await.unwrap().unwrap();

            tracing::debug!("Aggregator found sighash: {:?}", sighash);

            let final_sig = crate::musig2::aggregate_partial_signatures(
                verifiers_public_keys.clone(),
                None,
                false,
                &agg_nonce,
                partial_sigs,
                ByteArray32(sighash.to_byte_array()),
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

#[cfg(test)]
mod tests {
    use crate::{
        config::BridgeConfig,
        create_test_config_with_thread_name,
        database::Database,
        errors::BridgeError,
        initialize_database,
        servers::{
            create_aggregator_grpc_server, create_operator_grpc_server,
            create_verifier_grpc_server, create_watchtower_grpc_server,
        },
        utils::initialize_logger,
    };
    use crate::{
        create_actors,
        extended_rpc::ExtendedRpc,
        rpc::clementine::{self, clementine_aggregator_client::ClementineAggregatorClient},
        verifier::Verifier,
        watchtower::Watchtower,
    };
    use std::{env, thread};

    #[tokio::test]
    #[serial_test::serial]
    async fn aggregator_double_setup_fail() {
        let config = create_test_config_with_thread_name!(None);

        let (_, _, aggregator, _) = create_actors!(config);
        let mut aggregator_client =
            ClementineAggregatorClient::connect(format!("http://{}", aggregator.0))
                .await
                .unwrap();

        aggregator_client
            .setup(tonic::Request::new(clementine::Empty {}))
            .await
            .unwrap();

        assert!(aggregator_client
            .setup(tonic::Request::new(clementine::Empty {}))
            .await
            .is_err());
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn aggregator_setup_watchtower_winternitz_public_keys() {
        let mut config = create_test_config_with_thread_name!(None);

        let (_verifiers, _operators, aggregator, _watchtowers) = create_actors!(config.clone());
        let mut aggregator_client =
            ClementineAggregatorClient::connect(format!("http://{}", aggregator.0))
                .await
                .unwrap();

        aggregator_client
            .setup(tonic::Request::new(clementine::Empty {}))
            .await
            .unwrap();

        let watchtower = Watchtower::new(config.clone()).await.unwrap();
        let watchtower_wpks = watchtower
            .get_watchtower_winternitz_public_keys()
            .await
            .unwrap();

        let rpc = ExtendedRpc::new(
            config.bitcoin_rpc_url.clone(),
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
        )
        .await;

        config.db_name += "0"; // This modification is done by the create_actors_grpc function.
        let verifier = Verifier::new(rpc, config.clone()).await.unwrap();
        let verifier_wpks = verifier
            .db
            .get_watchtower_winternitz_public_keys(None, 0, 0)
            .await
            .unwrap();

        assert_eq!(
            watchtower_wpks[0..config.num_time_txs].to_vec(),
            verifier_wpks
        );
    }
}
