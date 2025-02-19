use super::clementine::{
    clementine_aggregator_server::ClementineAggregator, verifier_deposit_finalize_params,
    DepositParams, Empty, VerifierDepositFinalizeParams,
};
use crate::builder::sighash::SignatureInfo;
use crate::builder::transaction::{create_move_to_vault_txhandler, TxHandler};
use crate::config::BridgeConfig;
use crate::rpc::clementine::clementine_operator_client::ClementineOperatorClient;
use crate::rpc::clementine::clementine_verifier_client::ClementineVerifierClient;
use crate::rpc::clementine::VerifierDepositSignParams;
use crate::rpc::error::output_stream_ended_prematurely;
use crate::rpc::parser;
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
use bitcoin::TapSighash;
use futures::{
    future::try_join_all,
    stream::{BoxStream, TryStreamExt},
    FutureExt, Stream, StreamExt, TryFutureExt,
};
use secp256k1::musig::{MusigAggNonce, MusigPartialSignature, MusigPubNonce};
use std::future::Future;
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
    mut sighash_stream: impl Stream<Item = Result<(TapSighash, SignatureInfo), BridgeError>>
        + Unpin
        + Send
        + 'static,
    agg_nonce_sender: Sender<AggNonceQueueItem>,
) -> Result<MusigAggNonce, BridgeError> {
    let mut total_sigs = 0;
    tracing::info!("Starting nonce aggregation");
    while let Some(msg) = sighash_stream.next().await {
        let sighash = msg
            .map_err(|e| {
                tracing::error!("Error when reading from sighash stream: {}", e);
                BridgeError::RPCStreamEndedUnexpectedly("Sighash stream ended unexpectedly".into())
            })?
            .0;

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
    movetx_agg_nonce: impl Future<Output = Result<MusigAggNonce, Status>>,
) -> Result<(), BridgeError> {
    use verifier_deposit_finalize_params::Params;
    while let Some(queue_item) = final_sig_receiver.recv().await {
        let final_params = VerifierDepositFinalizeParams {
            params: Some(Params::SchnorrSig(queue_item.final_sig)),
        };

        for tx in &deposit_finalize_sender {
            tx.send(final_params.clone())
                .await
                .map_err(output_stream_ended_prematurely)?;
        }
    }

    let movetx_agg_nonce = movetx_agg_nonce.await?;
    // Send the movetx agg nonce to the verifiers.
    for tx in &deposit_finalize_sender {
        tx.send(VerifierDepositFinalizeParams {
            params: Some(Params::MoveTxAggNonce(
                movetx_agg_nonce.serialize().to_vec(),
            )),
        })
        .await
        .map_err(output_stream_ended_prematurely)?
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

    // Get the first responses from verifiers.
    let first_responses: Vec<clementine::NonceGenFirstResponse> =
        try_join_all(nonce_streams.iter_mut().map(|stream| async {
            parser::verifier::parse_nonce_gen_first_response(stream).await
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

/// Use items collected from the broadcast receiver for an async function call.
///
/// Handles the boilerplate of managing a receiver of a broadcast channel.
/// If receiver is lagged at any time (data is lost) an error is returned.
async fn collect_and_call<R, T, F, Fut>(
    rx: &mut tokio::sync::broadcast::Receiver<Vec<T>>,
    mut f: F,
) -> Result<R, Status>
where
    R: Default,
    T: Clone,
    F: FnMut(Vec<T>) -> Fut,
    Fut: Future<Output = Result<R, Status>>,
{
    loop {
        match rx.recv().await {
            Ok(params) => {
                f(params).await?;
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                break Err(BridgeError::RPCStreamEndedUnexpectedly(format!(
                    "lost {n} items due to lagging receiver"
                ))
                .into());
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break Ok(R::default()),
        }
    }
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

    async fn create_movetx_check_sig(
        &self,
        partial_sigs: Vec<Vec<u8>>,
        movetx_agg_nonce: MusigAggNonce,
        deposit_params: DepositParams,
    ) -> Result<TxHandler, Status> {
        let deposit_data = parser::parse_deposit_params(deposit_params)?;
        let musig_partial_sigs = parser::verifier::parse_partial_sigs(partial_sigs)?;

        // create move tx and calculate sighash
        let mut move_txhandler = create_move_to_vault_txhandler(
            deposit_data.deposit_outpoint,
            deposit_data.evm_address,
            &deposit_data.recovery_taproot_address,
            self.nofn_xonly_pk,
            self.config.user_takes_after,
            self.config.bridge_amount_sats,
            self.config.network,
        )?;
        let sighash = move_txhandler.calculate_script_spend_sighash_indexed(
            0,
            0,
            bitcoin::TapSighashType::Default,
        )?;

        // aggregate partial signatures
        let final_sig = crate::musig2::aggregate_partial_signatures(
            &self.config.verifiers_public_keys,
            None,
            movetx_agg_nonce,
            &musig_partial_sigs,
            Message::from_digest(sighash.to_byte_array()),
        )
        .map_err(|x| BridgeError::Error(format!("Aggregating MoveTx signatures failed {}", x)))?;

        // Put the signature in the tx
        move_txhandler.set_p2tr_script_spend_witness(&[final_sig.as_ref()], 0, 0)?;
        // Add fee bumper.
        let move_tx = move_txhandler.get_cached_tx();
        let _fee_payer_utxo = self
            .tx_sender
            .create_fee_payer_utxo(*move_txhandler.get_txid(), move_tx.weight())
            .await?;
        self.tx_sender.save_tx(move_tx).await?;

        // everything is fine, return the signed move tx
        // TODO: Sign the transaction correctly after we create taproot witness generation functions
        Ok(move_txhandler)
    }
}

#[async_trait]
impl ClementineAggregator for Aggregator {
    #[tracing::instrument(skip_all, err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn setup(&self, _request: Request<Empty>) -> Result<Response<Empty>, Status> {
        tracing::info!("Collecting verifier public keys...");
        let verifier_public_keys = try_join_all(self.verifier_clients.iter().map(|client| {
            let mut client = client.clone();
            async move {
                let verifier_params = client
                    .get_params(Request::new(Empty {}))
                    .await?
                    .into_inner();
                Ok::<_, Status>(verifier_params.public_key)
            }
        }))
        .shared(); // share this future so all the spawned threads can poll on it.

        tracing::debug!("Verifier public keys: {:?}", verifier_public_keys);

        let set_verifier_keys_handle = tokio::spawn({
            let verifier_clients = self.verifier_clients.clone();
            async move {
                tracing::info!("Setting up verifiers...");
                try_join_all(verifier_clients.into_iter().map(|mut verifier| {
                    let verifier_public_keys = verifier_public_keys.clone();
                    async move {
                        let verifier_public_keys = clementine::VerifierPublicKeys {
                            verifier_public_keys: verifier_public_keys.await?.clone(),
                        };
                        verifier
                            .set_verifiers(Request::new(verifier_public_keys))
                            .await?;
                        Ok::<_, Status>(())
                    }
                }))
                .await?;
                Ok::<_, Status>(())
            }
        });

        // Propagate Operators configurations to all verifier clients
        const CHANNEL_CAPACITY: usize = 1024 * 16;
        let (operator_params_tx, operator_params_rx) =
            tokio::sync::broadcast::channel(CHANNEL_CAPACITY);
        let operator_params_rx_handles = (0..self.config.num_verifiers)
            .map(|_| operator_params_rx.resubscribe())
            .collect::<Vec<_>>();

        let operators = self.operator_clients.clone();
        let get_operator_params_chunked_handle = tokio::spawn(async move {
            tracing::info!(clients = operators.len(), "Collecting operator details...");
            try_join_all(operators.iter().map(|operator| {
                let mut operator = operator.clone();
                let tx = operator_params_tx.clone();
                async move {
                    let stream = operator
                        .get_params(Request::new(Empty {}))
                        .await?
                        .into_inner();
                    tx.send(stream.try_collect::<Vec<_>>().await?)
                        .map_err(|e| {
                            BridgeError::Error(format!("failed to read operator params: {e}"))
                        })?;
                    Ok::<_, Status>(())
                }
            }))
            .await?;
            Ok::<_, Status>(())
        });

        let verifiers = self.verifier_clients.clone();
        let set_operator_params_handle = tokio::spawn(async move {
            tracing::info!("Informing verifiers of existing operators...");
            try_join_all(verifiers.iter().zip(operator_params_rx_handles).map(
                |(verifier, mut rx)| {
                    let verifier = verifier.clone();
                    async move {
                        collect_and_call(&mut rx, |params| {
                            let mut verifier = verifier.clone();
                            async move {
                                verifier.set_operator(futures::stream::iter(params)).await?;
                                Ok::<_, Status>(())
                            }
                        })
                        .await?;
                        Ok::<_, Status>(())
                    }
                },
            ))
            .await?;
            Ok::<_, Status>(())
        });

        // Propagate Watchtowers configuration to all verifier clients

        let (watchtower_params_tx, watchtower_params_rx) =
            tokio::sync::broadcast::channel(CHANNEL_CAPACITY);
        let watchtower_params_rx_handles = (0..self.config.num_verifiers)
            .map(|_| watchtower_params_rx.resubscribe())
            .collect::<Vec<_>>();

        let get_watchtower_params_chunked_handle = tokio::spawn({
            let watchtowers = self.watchtower_clients.clone();
            async move {
                tracing::info!("Collecting Winternitz public keys from watchtowers...");
                try_join_all(watchtowers.iter().map(|watchtower| {
                    let mut watchtower = watchtower.clone();
                    let tx = watchtower_params_tx.clone();
                    async move {
                        let stream = watchtower
                            .get_params(Request::new(Empty {}))
                            .await?
                            .into_inner();
                        tx.send(stream.try_collect::<Vec<_>>().await?)
                            .map_err(|e| {
                                BridgeError::Error(format!("failed to read watchtower params: {e}"))
                            })?;
                        Ok::<_, Status>(())
                    }
                }))
                .await?;
                Ok::<_, Status>(())
            }
        });

        let set_watchtower_params_handle = tokio::spawn({
            let verifiers = self.verifier_clients.clone();
            async move {
                tracing::info!("Sending Winternitz public keys to verifiers...");
                try_join_all(verifiers.iter().zip(watchtower_params_rx_handles).map(
                    |(verifier, mut rx)| {
                        let verifier = verifier.clone();
                        async move {
                            collect_and_call(&mut rx, |params| {
                                let mut verifier = verifier.clone();
                                async move {
                                    verifier
                                        .set_watchtower(futures::stream::iter(params))
                                        .await?;
                                    Ok::<_, Status>(())
                                }
                            })
                            .await?;
                            Ok::<_, Status>(())
                        }
                    },
                ))
                .await?;
                Ok::<_, Status>(())
            }
        });

        try_join_all([
            set_verifier_keys_handle,
            get_operator_params_chunked_handle,
            set_operator_params_handle,
            get_watchtower_params_chunked_handle,
            set_watchtower_params_handle,
        ])
        .await
        .map_err(|e| BridgeError::Error(format!("aggregator setup failed: {e}")))?
        .into_iter()
        .collect::<Result<Vec<_>, Status>>()?;

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
        request: Request<DepositParams>,
    ) -> Result<Response<clementine::Txid>, Status> {
        let deposit_params = request.into_inner();

        // Collect and distribute keys needed keys from operators and watchtowers to verifiers
        self.collect_and_distribute_keys(&deposit_params).await?;

        // Generate nonce streams for all verifiers.
        let num_required_sigs = calculate_num_required_nofn_sigs(&self.config);
        let (first_responses, nonce_streams) =
            create_nonce_streams(self.verifier_clients.clone(), num_required_sigs as u32 + 1)
                .await?; // ask for +1 for the final movetx signature, but don't send it on deposit_sign stage

        let mut partial_sig_streams =
            try_join_all(self.verifier_clients.iter().map(|verifier_client| {
                let mut verifier_client = verifier_client.clone();

                async move {
                    let (tx, rx) = tokio::sync::mpsc::channel(1280);
                    let stream = verifier_client
                        .deposit_sign(tokio_stream::wrappers::ReceiverStream::new(rx))
                        .await?
                        .into_inner();

                    Ok::<_, Status>((stream, tx))
                }
            }))
            .await?;

        // Create initial deposit session and send to verifiers
        let deposit_sign_session = DepositSignSession {
            deposit_params: Some(deposit_params.clone()),
            nonce_gen_first_responses: first_responses,
        };

        tracing::debug!("Sending deposit sign session to verifiers");
        for (_, tx) in partial_sig_streams.iter_mut() {
            let deposit_sign_param: VerifierDepositSignParams = deposit_sign_session.clone().into();

            tx.send(deposit_sign_param).await.map_err(|e| {
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
        let deposit_finalize_first_param: VerifierDepositFinalizeParams =
            deposit_sign_session.clone().into();
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

        let deposit_data = parser::parse_deposit_params(deposit_params.clone())?;

        // Create sighash stream for transaction signing
        let sighash_stream = Box::pin(create_nofn_sighash_stream(
            self.db.clone(),
            self.config.clone(),
            deposit_data,
            self.nofn_xonly_pk,
        ));

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
            self.config.verifiers_public_keys.clone(),
            final_sig_sender,
        ));

        tracing::debug!("Getting signatures from operators");
        // Get sigs from each operator in background
        let operator_sigs_fut = tokio::spawn(Aggregator::get_operator_sigs(
            self.operator_clients.clone(),
            self.config.clone(),
            deposit_sign_session,
        ));

        // Join the nonce aggregation handle to get the movetx agg nonce.
        let nonce_agg_handle = nonce_agg_handle
            .map_err(|_| Status::internal("panic when aggregating nonces"))
            .map(|res| -> Result<MusigAggNonce, Status> { res.and_then(|r| r.map_err(Into::into)) })
            .shared();

        // Start the deposit finalization pipe.
        let sig_dist_handle = tokio::spawn(signature_distributor(
            final_sig_receiver,
            deposit_finalize_sender.clone(),
            nonce_agg_handle.clone(),
        ));

        tracing::debug!(
            "Waiting for pipeline tasks to complete (nonce agg, sig agg, sig dist, operator sigs)"
        );
        // Wait for all pipeline tasks to complete
        try_join_all([nonce_dist_handle, sig_agg_handle, sig_dist_handle])
            .await
            .map_err(|_| Status::internal("panic when pipelining"))?;

        let operator_sigs = operator_sigs_fut
            .await
            .map_err(|_| Status::internal("panic when collecting operator signatures"))??;

        // send operators sigs to verifiers after all verifiers have signed
        let send_operator_sigs: Vec<_> = deposit_finalize_sender
            .iter()
            .map(|tx| async {
                for sigs in operator_sigs.iter() {
                    for sig in sigs.iter() {
                        let deposit_finalize_param: VerifierDepositFinalizeParams = sig.into();

                        tx.send(deposit_finalize_param).await.map_err(|e| {
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
                .map(|fut| async { Ok::<_, Status>(fut.await?.into_inner().partial_sig) }),
        )
        .await
        .map_err(|e| Status::internal(format!("Failed to finalize deposit: {:?}", e)))?;

        tracing::debug!("Received move tx partial sigs: {:?}", move_tx_partial_sigs);

        // Create the final move transaction and check the signatures
        let movetx_agg_nonce = nonce_agg_handle.await?;
        let signed_movetx_handler = self
            .create_movetx_check_sig(move_tx_partial_sigs, movetx_agg_nonce, deposit_params)
            .await?;
        let txid = *signed_movetx_handler.get_txid();

        Ok(Response::new(txid.into()))
    }
}

#[cfg(test)]
mod tests {
    use crate::actor::Actor;
    use crate::musig2::AggregateFromPublicKeys;
    use crate::rpc::clementine::clementine_operator_client::ClementineOperatorClient;
    use crate::rpc::clementine::clementine_verifier_client::ClementineVerifierClient;
    use crate::rpc::clementine::clementine_watchtower_client::ClementineWatchtowerClient;
    use crate::{builder, EVMAddress};
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
        create_actors, create_regtest_rpc,
        extended_rpc::ExtendedRpc,
        get_available_port,
        rpc::clementine::{self, clementine_aggregator_client::ClementineAggregatorClient},
    };
    use bitcoin::Txid;
    use bitcoincore_rpc::RpcApi;
    use std::str::FromStr;
    use std::time::Duration;
    use tokio::time::sleep;

    #[tokio::test]
    async fn aggregator_double_setup_fail() {
        let mut config = create_test_config_with_thread_name!(None);
        let _regtest = create_regtest_rpc!(config);

        let (_, _, mut aggregator, _) = create_actors!(config);

        aggregator
            .setup(tonic::Request::new(clementine::Empty {}))
            .await
            .unwrap();

        assert!(aggregator
            .setup(tonic::Request::new(clementine::Empty {}))
            .await
            .is_err());
    }

    #[tokio::test]
    #[ignore = "This test is also done during the deposit phase of test_deposit_and_sign_txs test"]
    async fn aggregator_setup_and_deposit() {
        let mut config = create_test_config_with_thread_name!(None);
        let _regtest = create_regtest_rpc!(config);

        let (_, _, mut aggregator, _) = create_actors!(config);

        tracing::info!("Setting up aggregator");
        let start = std::time::Instant::now();

        aggregator
            .setup(tonic::Request::new(clementine::Empty {}))
            .await
            .unwrap();

        tracing::info!("Setup completed in {:?}", start.elapsed());
        tracing::info!("Depositing");
        let deposit_start = std::time::Instant::now();
        aggregator
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
            })
            .await
            .unwrap();
        tracing::info!("Deposit completed in {:?}", deposit_start.elapsed());
    }

    #[tokio::test]
    async fn aggregator_deposit_movetx_lands_onchain() {
        let mut config = create_test_config_with_thread_name!(None);
        let regtest = create_regtest_rpc!(config);
        let rpc = regtest.rpc();

        let (_verifiers, _operators, mut aggregator, _watchtowers) = create_actors!(config);

        let evm_address = EVMAddress([1u8; 20]);
        let signer = Actor::new(
            config.secret_key,
            config.winternitz_secret_key,
            config.network,
        );

        let nofn_xonly_pk =
            bitcoin::XOnlyPublicKey::from_musig2_pks(config.verifiers_public_keys.clone(), None)
                .unwrap();

        let deposit_address = builder::address::generate_deposit_address(
            nofn_xonly_pk,
            signer.address.as_unchecked(),
            evm_address,
            config.bridge_amount_sats,
            config.network,
            config.user_takes_after,
        )
        .unwrap()
        .0;

        let deposit_outpoint = rpc
            .send_to_address(&deposit_address, config.bridge_amount_sats)
            .await
            .unwrap();
        rpc.mine_blocks(18).await.unwrap();

        aggregator
            .setup(tonic::Request::new(clementine::Empty {}))
            .await
            .unwrap();
        sleep(Duration::from_secs(3)).await;

        let movetx_txid: Txid = aggregator
            .new_deposit(DepositParams {
                deposit_outpoint: Some(deposit_outpoint.into()),
                evm_address: evm_address.0.to_vec(),
                recovery_taproot_address: signer.address.to_string(),
            })
            .await
            .unwrap()
            .into_inner()
            .try_into()
            .unwrap();
        rpc.mine_blocks(1).await.unwrap();
        sleep(Duration::from_secs(3)).await;

        let start = std::time::Instant::now();
        let timeout = 60;
        let tx = loop {
            if start.elapsed() > std::time::Duration::from_secs(timeout) {
                panic!("MoveTx did not land onchain within {timeout} seconds");
            }
            rpc.mine_blocks(1).await.unwrap();

            let tx_result = rpc
                .client
                .get_raw_transaction_info(&movetx_txid, None)
                .await;

            let tx_result = match tx_result {
                Ok(tx) => tx,
                Err(e) => {
                    tracing::error!("Error getting transaction: {:?}", e);
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
            };

            break tx_result;
        };

        assert!(tx.confirmations.unwrap() > 0);
    }
}
