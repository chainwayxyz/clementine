use super::clementine::{
    clementine_aggregator_server::ClementineAggregator, verifier_deposit_finalize_params,
    DepositParams, Empty, RawSignedMoveTx, VerifierDepositFinalizeParams,
};
use crate::builder::transaction::create_move_to_vault_txhandler;
use crate::config::BridgeConfig;
use crate::rpc::clementine::clementine_operator_client::ClementineOperatorClient;
use crate::rpc::clementine::clementine_verifier_client::ClementineVerifierClient;
use crate::rpc::parsers;
use crate::{
    aggregator::Aggregator,
    builder::sighash::{
        calculate_num_required_nofn_sigs, calculate_num_required_operator_sigs,
        create_nofn_sighash_stream,
    },
    errors::BridgeError,
    musig2::aggregate_nonces,
    rpc::clementine::{self, DepositSignSession},
};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::{Message, PublicKey};
use bitcoin::{Amount, TapSighash};
use futures::{future::try_join_all, stream::BoxStream, FutureExt, Stream, StreamExt};
use secp256k1::musig::{MusigAggNonce, MusigPartialSignature, MusigPubNonce};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tonic::{async_trait, Request, Response, Status, Streaming};

struct AggNonceQueueItem {
    agg_nonce: MusigAggNonce,
    sighash: TapSighash,
}

struct FinalSigQueueItem {
    final_sig: Vec<u8>,
}

/// For each expected sighash, we collect a batch of public nonces from all verifiers. We aggregate and send to the agg_nonce_sender. Then repeat for the next sighash.
async fn nonce_aggregator(
    mut nonce_streams: Vec<
        impl Stream<Item = Result<MusigPubNonce, BridgeError>> + Unpin + Send + 'static,
    >,
    mut sighash_stream: impl Stream<Item = Result<TapSighash, BridgeError>> + Unpin + Send + 'static,
    agg_nonce_sender: Sender<AggNonceQueueItem>,
) -> Result<MusigAggNonce, BridgeError> {
    let mut total_sigs = 0;
    tracing::info!("Starting nonce aggregation");
    while let Some(msg) = sighash_stream.next().await {
        let sighash = msg.map_err(|e| {
            tracing::error!("Error when reading from sighash stream: {}", e);
            BridgeError::RPCStreamEndedUnexpectedly("Sighash stream ended unexpectedly".into())
        })?;

        let pub_nonces = try_join_all(nonce_streams.iter_mut().enumerate().map(
            |(i, s)| async move {
                s.next().await.ok_or_else(|| {
                    BridgeError::RPCStreamEndedUnexpectedly(format!(
                        "Not enough nonces from verifier {i}",
                    ))
                })?
            },
        ))
        .await?;

        let agg_nonce = aggregate_nonces(pub_nonces.iter().collect::<Vec<_>>().as_slice());

        agg_nonce_sender
            .send(AggNonceQueueItem { agg_nonce, sighash })
            .await
            .map_err(|e| {
                BridgeError::RPCStreamEndedUnexpectedly(format!(
                    "Can't send aggregated nonces: {}",
                    e
                ))
            })?;

        total_sigs += 1;
    }

    if total_sigs == 0 {
        tracing::warn!("Sighash stream returned 0 signatures");
    }
    // Finally, aggregate nonces for the movetx signature
    let pub_nonces = try_join_all(nonce_streams.iter_mut().map(|s| async {
        s.next().await.ok_or_else(|| {
            BridgeError::RPCStreamEndedUnexpectedly(
                "Not enough nonces (expected movetx nonce)".into(),
            )
        })?
    }))
    .await?;

    let agg_nonce = aggregate_nonces(pub_nonces.iter().collect::<Vec<_>>().as_slice());

    Ok(agg_nonce)
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
    verifiers_public_keys: Vec<PublicKey>,
    final_sig_sender: Sender<FinalSigQueueItem>,
) -> Result<(), BridgeError> {
    while let Some((partial_sigs, queue_item)) = partial_sig_receiver.recv().await {
        let final_sig = crate::musig2::aggregate_partial_signatures(
            &verifiers_public_keys,
            None,
            queue_item.agg_nonce,
            &partial_sigs,
            Message::from_digest(queue_item.sighash.to_byte_array()),
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
    movetx_agg_nonce: MusigAggNonce,
) -> Result<(), BridgeError> {
    use verifier_deposit_finalize_params::Params;
    while let Some(queue_item) = final_sig_receiver.recv().await {
        let final_params = VerifierDepositFinalizeParams {
            params: Some(Params::SchnorrSig(queue_item.final_sig)),
        };

        for tx in &deposit_finalize_sender {
            tx.send(final_params.clone()).await.map_err(|e| {
                BridgeError::RPCStreamEndedUnexpectedly(format!("Can't send final params: {}", e))
            })?;
        }
    }

    // Send the movetx agg nonce to the verifiers.
    for tx in &deposit_finalize_sender {
        tx.send(VerifierDepositFinalizeParams {
            params: Some(Params::MoveTxAggNonce(
                movetx_agg_nonce.serialize().to_vec(),
            )),
        })
        .await
        .unwrap();
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

    /// For a specific deposit, gets needed signatures from each operator and returns a Vec with signatures from each operator
    async fn get_operator_sigs(
        operator_clients: Vec<ClementineOperatorClient<tonic::transport::Channel>>,
        config: BridgeConfig,
        mut deposit_sign_session: DepositSignSession,
    ) -> Result<Vec<Vec<Signature>>, BridgeError> {
        deposit_sign_session.nonce_gen_first_responses = Vec::new(); // not needed for operators
        let mut operator_sigs_streams =
            // create deposit sign streams with each operator
            try_join_all(operator_clients.into_iter().map(|mut operator_client| {
                let sign_session = deposit_sign_session.clone();
                async move {
                    let stream = operator_client
                        .deposit_sign(tonic::Request::new(sign_session))
                        .await?;
                    Ok::<_, Status>(stream.into_inner())
                }
            }))
                .await?;
        // calculate number of signatures needed from each operator
        let needed_sigs = calculate_num_required_operator_sigs(&config);
        // get signatures from each operator's signature streams
        let operator_sigs = try_join_all(operator_sigs_streams.iter_mut().map(|stream| async {
            let mut sigs: Vec<Signature> = Vec::with_capacity(needed_sigs);
            while let Some(sig) = stream.message().await? {
                sigs.push(Signature::from_slice(&sig.schnorr_sig)?);
            }
            Ok::<_, BridgeError>(sigs)
        }))
        .await?;
        // check if all signatures are received
        for (idx, sigs) in operator_sigs.iter().enumerate() {
            if sigs.len() != needed_sigs {
                return Err(BridgeError::Error(format!(
                    "Not all operator sigs received from op: {}.\n Expected: {}, got: {}",
                    idx,
                    needed_sigs,
                    sigs.len()
                )));
            }
        }
        Ok(operator_sigs)
    }

    fn create_movetx_check_sig(
        &self,
        partial_sigs: Vec<Vec<u8>>,
        movetx_agg_nonce: MusigAggNonce,
        deposit_params: DepositParams,
    ) -> Result<RawSignedMoveTx, Status> {
        let (deposit_outpoint, evm_address, recovery_taproot_address, user_takes_after) =
            parsers::parse_deposit_params(deposit_params)?;
        let musig_partial_sigs: Vec<MusigPartialSignature> = partial_sigs
            .iter()
            .map(|sig: &Vec<u8>| MusigPartialSignature::from_slice(sig))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                BridgeError::RPCParamMalformed(
                    "Partial sigs for movetx could not be parsed into MusigPartialSignature",
                    e.to_string(),
                )
            })?;

        // create move tx and calculate sighash
        let mut move_txhandler = create_move_to_vault_txhandler(
            deposit_outpoint,
            evm_address,
            &recovery_taproot_address,
            self.nofn_xonly_pk,
            user_takes_after,
            self.config.bridge_amount_sats,
            self.config.network,
        );
        let sighash = move_txhandler.calculate_script_spend_sighash(0, 0, None)?;

        // aggregate partial signatures
        let _final_sig = crate::musig2::aggregate_partial_signatures(
            &self.config.verifiers_public_keys,
            None,
            movetx_agg_nonce,
            &musig_partial_sigs,
            Message::from_digest(sighash.to_byte_array()),
        )
        .map_err(|x| BridgeError::Error(format!("Aggregating MoveTx signatures failed {}", x)))?;

        // everything is fine, return the signed move tx
        let _move_tx = move_txhandler.tx;
        // TODO: Sign the transaction correctly after we create taproot witness generation functions
        Ok(RawSignedMoveTx { raw_tx: vec![1, 2] })
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
                let mut responses = Vec::new();
                let mut params_stream = client
                    .get_params(Request::new(Empty {}))
                    .await?
                    .into_inner();
                while let Some(response) = params_stream.message().await? {
                    responses.push(response);
                }

                Ok::<_, Status>(responses)
            }
        }))
        .await?;

        tracing::info!("Informing verifiers for existing operators...");
        try_join_all(self.verifier_clients.iter().map(|client| {
            let mut client = client.clone();
            let operator_params = operator_params.clone();

            async move {
                for params in operator_params {
                    let (tx, rx) = tokio::sync::mpsc::channel(1280);
                    let future =
                        client.set_operator(tokio_stream::wrappers::ReceiverStream::new(rx));

                    for param in params {
                        tx.send(param).await.unwrap();
                    }

                    future.await?; // TODO: This is dangerous: If channel size becomes not sufficient, this will block forever.
                }

                Ok::<_, tonic::Status>(())
            }
        }))
        .await?;

        tracing::info!("Collecting Winternitz public keys from watchtowers...");
        let watchtower_params = try_join_all(self.watchtower_clients.iter().map(|client| {
            let mut client = client.clone();
            async move {
                let mut responses = Vec::new();
                let mut params_stream = client
                    .get_params(Request::new(Empty {}))
                    .await?
                    .into_inner();
                while let Some(response) = params_stream.message().await? {
                    responses.push(response);
                }

                Ok::<_, Status>(responses)
            }
        }))
        .await?;

        tracing::info!("Sending Winternitz public keys to verifiers...");
        try_join_all(self.verifier_clients.iter().map(|client| {
            let mut client = client.clone();
            let watchtower_params = watchtower_params.clone();

            async move {
                for params in watchtower_params {
                    let (tx, rx) = tokio::sync::mpsc::channel(1280);

                    let future =
                        client.set_watchtower(tokio_stream::wrappers::ReceiverStream::new(rx));
                    for param in params {
                        tx.send(param).await.unwrap();
                    }

                    future.await?; // TODO: This is dangerous: If channel size becomes not sufficient, this will block forever.
                }

                Ok::<_, tonic::Status>(())
            }
        }))
        .await?;

        Ok(Response::new(Empty {}))
    }

    /// Handles a new deposit request from a user. This function coordinates the signing process
    /// between verifiers to create a valid move transaction. It ensures a covenant using pre-signed NofN transactions.
    /// It also collects signatures from operators to ensure that the operators can be slashed if they act maliciously.
    ///
    /// Overview:
    /// 1. Receive and parse deposit parameters from user
    /// 2. Signs all NofN transactions with verifiers using MuSig2:
    ///    - Creates nonce streams with verifiers (get pub nonces for each transaction)
    ///    - Opens deposit signing streams with verifiers (sends aggnonces for each transaction, receives partial sigs)
    ///    - Opens deposit finalization streams with verifiers (sends final signatures, receives movetx signatures)
    /// 3. Collects signatures from operators
    /// 4. Waits for all tasks to complete
    /// 5. Returns signed move transaction
    ///
    /// The following pipelines are used to coordinate the signing process, these move the data between the verifiers and the aggregator:
    ///    - Nonce aggregation
    ///    - Nonce distribution
    ///    - Signature aggregation
    ///    - Signature distribution
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn new_deposit(
        &self,
        deposit_params_req: Request<DepositParams>,
    ) -> Result<Response<RawSignedMoveTx>, Status> {
        tracing::info!("Received new deposit request: {:?}", deposit_params_req);

        // Extract and validate deposit parameters
        let deposit_params = deposit_params_req.get_ref().clone();
        let (deposit_outpoint, evm_address, recovery_taproot_address, user_takes_after) =
            parsers::parse_deposit_params(deposit_params.clone())?;
        let verifiers_public_keys = self.config.verifiers_public_keys.clone();

        tracing::debug!("Parsed deposit params");

        // Generate nonce streams for all verifiers.
        let num_required_sigs = calculate_num_required_nofn_sigs(&self.config);
        let (first_responses, nonce_streams) =
            create_nonce_streams(self.verifier_clients.clone(), num_required_sigs as u32 + 1)
                .await?; // ask for +1 for the final movetx signature, but don't send it on deposit_sign stage

        // Create deposit signing streams with each verifier
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

        // Create initial deposit session and send to verifiers
        let deposit_sign_session = DepositSignSession {
            deposit_params: Some(deposit_params_req.into_inner()),
            nonce_gen_first_responses: first_responses,
        };

        tracing::debug!("Sending deposit sign session to verifiers");

        // Send deposit session to each verifier
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

        // Set up deposit finalization streams
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

        // Send initial finalization params
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

        // Create sighash stream for transaction signing
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

        // Create channels for pipeline communication
        let (agg_nonce_sender, agg_nonce_receiver) = channel(32);
        let (partial_sig_sender, partial_sig_receiver) = channel(32);
        let (final_sig_sender, final_sig_receiver) = channel(32);

        // Start the nonce aggregation pipe.
        let nonce_agg_handle = tokio::spawn(nonce_aggregator(
            nonce_streams,
            sighash_stream,
            agg_nonce_sender,
        ));

        // Start the nonce distribution pipe.
        let nonce_dist_handle = tokio::spawn(nonce_distributor(
            agg_nonce_receiver,
            partial_sig_streams,
            partial_sig_sender,
        ));

        // Start the signature aggregation pipe.
        let sig_agg_handle = tokio::spawn(signature_aggregator(
            partial_sig_receiver,
            verifiers_public_keys,
            final_sig_sender,
        ));

        // Join the nonce aggregation handle to get the movetx agg nonce.
        let movetx_agg_nonce = nonce_agg_handle.await.unwrap()?;

        // Start the deposit finalization pipe.
        let sig_dist_handle = tokio::spawn(signature_distributor(
            final_sig_receiver,
            deposit_finalize_sender.clone(),
            movetx_agg_nonce,
        ));

        tracing::debug!("Getting signatures from operators");
        // Get sigs from each operator in background
        let operator_sigs_fut = tokio::spawn(Aggregator::get_operator_sigs(
            self.operator_clients.clone(),
            self.config.clone(),
            deposit_sign_session,
        ));

        tracing::debug!(
            "Waiting for pipeline tasks to complete (nonce agg, sig agg, sig dist, operator sigs)"
        );
        // Wait for all pipeline tasks to complete
        nonce_dist_handle.await.unwrap()?;
        sig_agg_handle.await.unwrap()?;
        sig_dist_handle.await.unwrap()?;
        let operator_sigs = operator_sigs_fut.await.unwrap()?;

        // send operators sigs to verifiers after all verifiers have signed
        let send_operator_sigs: Vec<_> = deposit_finalize_sender
            .iter()
            .map(|tx| async {
                for sigs in operator_sigs.iter() {
                    for sig in sigs.iter() {
                        tx.send(VerifierDepositFinalizeParams {
                            params: Some(verifier_deposit_finalize_params::Params::SchnorrSig(
                                sig.serialize().to_vec(),
                            )),
                        })
                        .await
                        .map_err(|e| {
                            BridgeError::RPCStreamEndedUnexpectedly(format!(
                                "Can't send operator sigs to verifier: {}",
                                e
                            ))
                        })?;
                    }
                }
                Ok::<(), BridgeError>(())
            })
            .collect();

        // wait until all operator sigs are sent to every verifier
        try_join_all(send_operator_sigs).await?;

        tracing::debug!("Waiting for deposit finalization");

        // Collect partial signatures for move transaction
        let move_tx_partial_sigs = try_join_all(
            deposit_finalize_futures
                .iter_mut()
                .map(|f| async { Ok::<_, Status>(f.await.unwrap().into_inner().partial_sig) }),
        )
        .await
        .map_err(|e| Status::internal(format!("Failed to finalize deposit: {:?}", e)))?;

        tracing::debug!("Received move tx partial sigs: {:?}", move_tx_partial_sigs);
        // Create the final move transaction and check the signatures
        let raw_signed_movetx =
            self.create_movetx_check_sig(move_tx_partial_sigs, movetx_agg_nonce, deposit_params)?;

        Ok(Response::new(raw_signed_movetx))
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
            .get_watchtower_winternitz_public_keys(None, 0, 0) // TODO: Change this, this index should not be 0 for the watchtower.
            .await
            .unwrap();
        tracing::info!("watchtower_wpks length: {:?}", watchtower_wpks.len());
        tracing::info!("verifier_wpks length: {:?}", verifier_wpks.len());
        tracing::info!(
            "config.num_time_txs: {:?}",
            config.num_sequential_collateral_txs
        );
        tracing::info!(
            "config.num_kickoffs_per_timetx: {:?}",
            config.num_kickoffs_per_sequential_collateral_tx
        );
        assert_eq!(
            config.num_sequential_collateral_txs * config.num_kickoffs_per_sequential_collateral_tx,
            verifier_wpks.len()
        );
        assert!(
            watchtower_wpks[0..config.num_sequential_collateral_txs
                * config.num_kickoffs_per_sequential_collateral_tx]
                .to_vec()
                == verifier_wpks,
            "Winternitz keys of watchtower and verifier are not equal"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn aggregator_setup_watchtower_challenge_addresses() {
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
        tracing::info!("watchtower config: {:#?}", watchtower.config);
        let watchtower_wpks = watchtower
            .get_watchtower_winternitz_public_keys()
            .await
            .unwrap();
        let watchtower_challenge_addresses = watchtower
            .get_watchtower_challenge_addresses()
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
        tracing::info!("verifier config: {:#?}", verifier.config);
        let verifier_wpks = verifier
            .db
            .get_watchtower_winternitz_public_keys(None, 0, 0)
            .await
            .unwrap();
        let verifier_challenge_addresses_0 = verifier
            .db
            .get_watchtower_challenge_addresses(None, 0, 0)
            .await
            .unwrap();
        let verifier_challenge_addresses_1 = verifier
            .db
            .get_watchtower_challenge_addresses(None, 1, 0)
            .await
            .unwrap();
        let verifier_challenge_addresses_2 = verifier
            .db
            .get_watchtower_challenge_addresses(None, 2, 0)
            .await
            .unwrap();
        let verifier_challenge_addresses_3 = verifier
            .db
            .get_watchtower_challenge_addresses(None, 3, 0)
            .await
            .unwrap();
        tracing::info!(
            "watchtower_challenge_addresses length: {:?}",
            watchtower_challenge_addresses.len()
        );
        tracing::info!(
            "verifier_challenge_addresses length: {:?}",
            verifier_challenge_addresses_0.len()
        );
        assert_eq!(
            config.num_kickoffs_per_sequential_collateral_tx
                * config.num_kickoffs_per_sequential_collateral_tx,
            verifier_wpks.len()
        );
        assert_eq!(
            config.num_kickoffs_per_sequential_collateral_tx
                * config.num_kickoffs_per_sequential_collateral_tx,
            verifier_challenge_addresses_0.len()
        );
        tracing::info!(
            "watchtower_challenge_addresses: {:?}",
            watchtower_challenge_addresses
        );
        tracing::info!(
            "verifier_challenge_addresses_0: {:?}",
            verifier_challenge_addresses_0
        );
        tracing::info!(
            "verifier_challenge_addresses_1: {:?}",
            verifier_challenge_addresses_1
        );
        tracing::info!(
            "verifier_challenge_addresses_2: {:?}",
            verifier_challenge_addresses_2
        );
        tracing::info!(
            "verifier_challenge_addresses_3: {:?}",
            verifier_challenge_addresses_3
        );
        assert!(
            watchtower_wpks[0..config.num_kickoffs_per_sequential_collateral_tx
                * config.num_kickoffs_per_sequential_collateral_tx]
                .to_vec()
                == verifier_wpks,
            "Winternitz keys of watchtower and verifier are not equal"
        );
        assert!(
            watchtower_challenge_addresses[0..config.num_kickoffs_per_sequential_collateral_tx
                * config.num_kickoffs_per_sequential_collateral_tx]
                .to_vec()
                == verifier_challenge_addresses_2, // Caveat: https://github.com/chainwayxyz/clementine/issues/478
            "Challenge addresses of watchtower and verifier are not equal"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn aggregator_setup_and_deposit() {
        let config = create_test_config_with_thread_name!(None);

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
