use super::clementine::{
    clementine_aggregator_server::ClementineAggregator, verifier_deposit_finalize_params,
    DepositParams, Empty, RawSignedMoveTx, VerifierDepositFinalizeParams,
};
use crate::rpc::clementine::clementine_verifier_client::ClementineVerifierClient;
use crate::{
    aggregator::Aggregator,
    builder::sighash::{calculate_num_required_sigs, create_nofn_sighash_stream},
    errors::BridgeError,
    musig2::aggregate_nonces,
    rpc::clementine::{self, DepositSignSession},
    EVMAddress,
};
use bitcoin::hashes::Hash;
use bitcoin::{Amount, TapSighash};
use futures::{future::try_join_all, stream::BoxStream, FutureExt, Stream, StreamExt};
use secp256k1::musig::{MusigAggNonce, MusigPartialSignature, MusigPubNonce};
use secp256k1::Message;
use std::thread;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tonic::{async_trait, Request, Response, Status, Streaming};

struct AggNonceQueueItem {
    agg_nonce: MusigAggNonce,
    sighash: TapSighash,
}

struct FinalSigQueueItem {
    final_sig: Vec<u8>,
}

/// Collects public nonces from given streams and aggregates them.
async fn nonce_aggregator(
    mut nonce_streams: Vec<
        impl Stream<Item = Result<MusigPubNonce, BridgeError>> + Unpin + Send + 'static,
    >,
    mut sighash_stream: impl Stream<Item = Result<TapSighash, BridgeError>> + Unpin + Send + 'static,
    agg_nonce_sender: Sender<AggNonceQueueItem>,
) -> Result<(), BridgeError> {
    while let Ok(sighash) = sighash_stream.next().await.transpose() {
        let pub_nonces = try_join_all(nonce_streams.iter_mut().map(|s| async {
            s.next().await.ok_or_else(|| {
                BridgeError::RPCStreamEndedUnexpectedly("Not enough nonces".into())
            })?
        }))
        .await?;

        let agg_nonce = aggregate_nonces(pub_nonces);

        agg_nonce_sender
            .send(AggNonceQueueItem {
                agg_nonce,
                sighash: sighash.ok_or(BridgeError::RPCStreamEndedUnexpectedly(
                    "Not enough sighashes".into(),
                ))?,
            })
            .await
            .map_err(|e| {
                BridgeError::RPCStreamEndedUnexpectedly(format!(
                    "Can't send aggregated nonces: {}",
                    e
                ))
            })?;
    }

    Ok(())
}

/// Reroutes aggregated nonces to the signature aggregator.
async fn nonce_distributor(
    mut agg_nonce_receiver: Receiver<AggNonceQueueItem>,
    mut partial_sig_streams: Vec<(
        Streaming<clementine::PartialSig>,
        Sender<clementine::VerifierDepositSignParams>,
    )>,
    partial_sig_sender: Sender<(Vec<MusigPartialSignature>, AggNonceQueueItem)>,
) -> Result<(), BridgeError> {
    while let Some(queue_item) = agg_nonce_receiver.recv().await {
        let agg_nonce_wrapped = clementine::VerifierDepositSignParams {
            params: Some(clementine::verifier_deposit_sign_params::Params::AggNonce(
                queue_item.agg_nonce.serialize().to_vec(),
            )),
        };

        for (_, tx) in partial_sig_streams.iter_mut() {
            tx.send(agg_nonce_wrapped.clone()).await.map_err(|e| {
                BridgeError::RPCStreamEndedUnexpectedly(format!(
                    "Can't send aggregated nonces: {}",
                    e
                ))
            })?;
        }

        let partial_sigs = try_join_all(partial_sig_streams.iter_mut().map(|(stream, _)| async {
            let partial_sig = stream
                .message()
                .await?
                .ok_or(BridgeError::Error("No partial sig received".into()))?;

            Ok::<_, BridgeError>(MusigPartialSignature::from_slice(&partial_sig.partial_sig)?)
        }))
        .await?;

        partial_sig_sender
            .send((partial_sigs, queue_item))
            .await
            .map_err(|e| {
                BridgeError::RPCStreamEndedUnexpectedly(format!("Can't send partial sigs: {}", e))
            })?;
    }

    Ok(())
}

/// Collects partial signatures from given stream and aggregates them.
async fn signature_aggregator(
    mut partial_sig_receiver: Receiver<(Vec<MusigPartialSignature>, AggNonceQueueItem)>,
    verifiers_public_keys: Vec<secp256k1::PublicKey>,
    final_sig_sender: Sender<FinalSigQueueItem>,
) -> Result<(), BridgeError> {
    while let Some((partial_sigs, queue_item)) = partial_sig_receiver.recv().await {
        let final_sig = crate::musig2::aggregate_partial_signatures(
            verifiers_public_keys.clone(),
            None,
            false,
            queue_item.agg_nonce,
            partial_sigs,
            Message::from_digest(queue_item.sighash.as_raw_hash().to_byte_array()),
        )?;

        final_sig_sender
            .send(FinalSigQueueItem {
                final_sig: final_sig.serialize().to_vec(),
            })
            .await
            .map_err(|e| {
                BridgeError::RPCStreamEndedUnexpectedly(format!("Can't send final sigs: {}", e))
            })?;
    }

    Ok(())
}

/// Reroutes aggregated signatures to the caller.
async fn signature_distributor(
    mut final_sig_receiver: Receiver<FinalSigQueueItem>,
    deposit_finalize_sender: Vec<Sender<VerifierDepositFinalizeParams>>,
) -> Result<(), BridgeError> {
    while let Some(queue_item) = final_sig_receiver.recv().await {
        let final_params = VerifierDepositFinalizeParams {
            params: Some(verifier_deposit_finalize_params::Params::SchnorrSig(
                queue_item.final_sig,
            )),
        };

        for tx in &deposit_finalize_sender {
            tx.send(final_params.clone()).await.map_err(|e| {
                BridgeError::RPCStreamEndedUnexpectedly(format!("Can't send final params: {}", e))
            })?;
        }
    }

    Ok(())
}

/// Creates a stream of nonces from verifiers.
/// This will automatically get's the first response from the verifiers.
///
/// # Returns
///
/// - Vec<[`clementine::NonceGenFirstResponse`]>: First response from each verifier
/// - Vec<BoxStream<Result<[`MusigPubNonce`], BridgeError>>>: Stream of nonces from each verifier
async fn create_nonce_streams(
    verifier_clients: Vec<ClementineVerifierClient<tonic::transport::Channel>>,
    num_nonces: u32,
) -> Result<
    (
        Vec<clementine::NonceGenFirstResponse>,
        Vec<BoxStream<'static, Result<MusigPubNonce, BridgeError>>>,
    ),
    BridgeError,
> {
    let mut nonce_streams = try_join_all(verifier_clients.into_iter().map(|client| {
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

    // Get the first responses.
    let first_responses: Vec<clementine::NonceGenFirstResponse> =
        try_join_all(nonce_streams.iter_mut().map(|stream| async {
            let nonce_gen_first_response = stream
                .message()
                .await?
                .ok_or(BridgeError::RPCStreamEndedUnexpectedly(
                    "NonceGen returns nothing".to_string(),
                ))?
                .response
                .ok_or(BridgeError::RPCStreamEndedUnexpectedly(
                    "NonceGen response field is empty".to_string(),
                ))?;

            if let clementine::nonce_gen_response::Response::FirstResponse(
                nonce_gen_first_response,
            ) = nonce_gen_first_response
            {
                Ok(nonce_gen_first_response)
            } else {
                Err(BridgeError::RPCInvalidResponse(
                    "NonceGen response is not FirstResponse".to_string(),
                ))
            }
        }))
        .await?;

    let transformed_streams = nonce_streams
        .into_iter()
        .map(|stream| {
            stream
                .map(|result| Aggregator::extract_pub_nonce(result?.response))
                .boxed()
        })
        .collect::<Vec<_>>();

    Ok((first_responses, transformed_streams))
}

impl Aggregator {
    // Extracts pub_nonce from given stream.
    fn extract_pub_nonce(
        response: Option<clementine::nonce_gen_response::Response>,
    ) -> Result<MusigPubNonce, BridgeError> {
        match response
            .ok_or_else(|| BridgeError::Error("NonceGen response is empty".to_string()))?
        {
            clementine::nonce_gen_response::Response::PubNonce(pub_nonce) => {
                Ok(MusigPubNonce::from_slice(&pub_nonce)?)
            }
            _ => Err(BridgeError::Error(
                "Expected PubNonce in response".to_string(),
            )),
        }
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
        tracing::info!("Recieved new deposit request: {:?}", deposit_params_req);

        let deposit_params = deposit_params_req.into_inner();

        let deposit_outpoint: bitcoin::OutPoint = deposit_params
            .clone()
            .deposit_outpoint
            .ok_or(Status::internal("No deposit outpoint received"))
            .clone()?
            .try_into()?;
        let evm_address: EVMAddress = deposit_params
            .evm_address
            .clone()
            .try_into()
            .map_err(|e: &str| BridgeError::RPCParamMalformed("evm_address", e.to_string()))?;
        let recovery_taproot_address = deposit_params
            .clone()
            .recovery_taproot_address
            .clone()
            .parse::<bitcoin::Address<_>>()
            .map_err(|e| {
                BridgeError::RPCParamMalformed("recovery_taproot_address", e.to_string())
            })?;
        let user_takes_after = deposit_params.user_takes_after;
        let verifiers_public_keys = self.config.verifiers_public_keys.clone();

        tracing::debug!("Parsed deposit params");

        // Generate nonce streams for all verifiers.
        let num_required_sigs = calculate_num_required_sigs(
            self.config.num_operators,
            self.config.num_time_txs,
            self.config.num_watchtowers,
        );
        let (first_responses, nonce_streams) =
            create_nonce_streams(self.verifier_clients.clone(), num_required_sigs as u32).await?;

        // Open the deposit signing streams for each verifier.
        let mut partial_sig_streams =
            try_join_all(self.verifier_clients.iter().map(|verifier_client| {
                let mut verifier_client = verifier_client.clone();

                async move {
                    let (tx, rx) = tokio::sync::mpsc::channel(1280);
                    let stream = verifier_client
                        .deposit_sign(tokio_stream::wrappers::ReceiverStream::new(rx))
                        .await?;

                    Ok::<_, Status>((stream.into_inner(), tx))
                }
            }))
            .await?;

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
            .map_err(|e| {
                Status::internal(format!("Failed to send deposit sign session: {:?}", e))
            })?;
        }

        let mut deposit_finalize_clients = self.verifier_clients.clone();
        let deposit_finalize_streams = try_join_all(deposit_finalize_clients.iter_mut().map(
            |verifier_client| async move {
                let (tx, rx) = tokio::sync::mpsc::channel(1280);
                let receiver_stream = tokio_stream::wrappers::ReceiverStream::new(rx);

                let deposit_finalize_futures =
                    verifier_client.deposit_finalize(receiver_stream).boxed();

                Ok::<_, Status>((deposit_finalize_futures, tx))
            },
        ))
        .await?;
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
            tx.send(deposit_finalize_first_param.clone())
                .await
                .map_err(|e| {
                    Status::internal(format!(
                        "Failed to send deposit finalize first param: {:?}",
                        e
                    ))
                })?;
        }

        let sighash_stream = create_nofn_sighash_stream(
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
        );
        let sighash_stream = Box::pin(sighash_stream);

        let (agg_nonce_sender, agg_nonce_receiver) = channel(32);
        let (partial_sig_sender, partial_sig_receiver) = channel(32);
        let (final_sig_sender, final_sig_receiver) = channel(32);

        // Spawn all pipeline tasks
        let nonce_agg_handle = thread::spawn(|| {
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(nonce_aggregator(
                    nonce_streams,
                    sighash_stream,
                    agg_nonce_sender,
                ))
        });
        let nonce_dist_handle = tokio::spawn(nonce_distributor(
            agg_nonce_receiver,
            partial_sig_streams,
            partial_sig_sender,
        ));
        let sig_agg_handle = thread::spawn(|| {
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(signature_aggregator(
                    partial_sig_receiver,
                    verifiers_public_keys,
                    final_sig_sender,
                ))
        });
        let sig_dist_handle = tokio::spawn(signature_distributor(
            final_sig_receiver,
            deposit_finalize_sender,
        ));

        nonce_agg_handle.join().unwrap().unwrap();
        try_join_all(vec![nonce_dist_handle]).await.unwrap();
        sig_agg_handle.join().unwrap().unwrap();
        try_join_all(vec![sig_dist_handle]).await.unwrap();

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
    use bitcoin::Txid;

    use crate::{
        config::BridgeConfig,
        create_test_config_with_thread_name,
        database::Database,
        errors::BridgeError,
        initialize_database,
        rpc::clementine::DepositParams,
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
    use std::{env, str::FromStr, thread};

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

    #[tokio::test]
    #[serial_test::serial]
    async fn aggregator_setup_and_deposit() {
        let mut config = create_test_config_with_thread_name!(None);

        // Change default values for making the test faster.
        config.num_time_txs = 1;
        config.num_operators = 1;
        config.num_verifiers = 1;
        config.num_watchtowers = 1;

        let aggregator = create_actors!(config).2;
        let mut aggregator_client =
            ClementineAggregatorClient::connect(format!("http://{}", aggregator.0))
                .await
                .unwrap();

        aggregator_client
            .setup(tonic::Request::new(clementine::Empty {}))
            .await
            .unwrap();

        aggregator_client
            .new_deposit(DepositParams {
                deposit_outpoint: Some(
                    bitcoin::OutPoint {
                        txid: Txid::from_str(
                            "17e3fc7aae1035e77a91e96d1ba27f91a40a912cf669b367eb32c13a8f82bb02",
                        )
                        .unwrap(),
                        vout: 0,
                    }
                    .into(),
                ),
                evm_address: [1u8; 20].to_vec(),
                recovery_taproot_address:
                    "tb1pk8vus63mx5zwlmmmglq554kwu0zm9uhswqskxg99k66h8m3arguqfrvywa".to_string(),
                user_takes_after: 5,
            })
            .await
            .unwrap();
    }
}
