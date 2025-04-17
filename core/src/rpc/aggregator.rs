use super::clementine::{
    clementine_aggregator_server::ClementineAggregator, verifier_deposit_finalize_params,
    DepositParams, Empty, VerifierDepositFinalizeParams,
};
use super::clementine::{AggregatorWithdrawResponse, Deposit, VerifierPublicKeys, WithdrawParams};
use crate::builder::sighash::SignatureInfo;
use crate::builder::transaction::{
    create_move_to_vault_txhandler, Actors, DepositData, DepositInfo, Signed, TransactionType,
    TxHandler,
};
use crate::config::BridgeConfig;
use crate::errors::ResultExt;
use crate::musig2::AggregateFromPublicKeys;
use crate::rpc::clementine::clementine_operator_client::ClementineOperatorClient;
use crate::rpc::clementine::clementine_verifier_client::ClementineVerifierClient;
use crate::rpc::clementine::VerifierDepositSignParams;
use crate::rpc::parser;
use crate::tx_sender::{FeePayingType, TxMetadata};
use crate::{
    aggregator::Aggregator,
    builder::sighash::create_nofn_sighash_stream,
    errors::BridgeError,
    musig2::aggregate_nonces,
    rpc::clementine::{self, DepositSignSession},
};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::{Message, PublicKey};
use bitcoin::{TapSighash, XOnlyPublicKey};
use eyre::{Context, OptionExt};
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

#[derive(Debug, thiserror::Error)]
pub enum AggregatorError {
    #[error("Failed to receive from {stream_name} stream.")]
    InputStreamEndedEarlyUnknownSize { stream_name: String },
    #[error("Failed to send to {stream_name} stream.")]
    OutputStreamEndedEarly { stream_name: String },
    #[error("Failed to send request to {request_name} stream.")]
    RequestFailed { request_name: String },
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

    // We assume the sighash stream returns the correct number of items.
    while let Some(msg) = sighash_stream.next().await {
        let (sighash, siginfo) = msg.wrap_err("Sighash stream failed")?;

        total_sigs += 1;

        let pub_nonces = try_join_all(nonce_streams.iter_mut().enumerate().map(
            |(i, s)| async move {
                s.next()
                    .await
                    .transpose()? // Return the inner error if it exists
                    .ok_or_else(|| -> eyre::Report {
                        AggregatorError::InputStreamEndedEarlyUnknownSize {
                            // Return an early end error if the stream is empty
                            stream_name: format!("Nonce stream {i}"),
                        }
                        .into()
                    })
            },
        ))
        .await
        .wrap_err_with(|| {
            format!("Failed to aggregate nonces for sighash with info: {siginfo:?}")
        })?;

        tracing::debug!(
            "Received nonces for signature id {:?} in nonce_aggregator",
            siginfo.signature_id
        );

        // TODO: consider spawn_blocking here
        let agg_nonce = aggregate_nonces(pub_nonces.iter().collect::<Vec<_>>().as_slice());

        agg_nonce_sender
            .send(AggNonceQueueItem { agg_nonce, sighash })
            .await
            .wrap_err_with(|| AggregatorError::OutputStreamEndedEarly {
                stream_name: "nonce_aggregator".to_string(),
            })?;

        tracing::debug!(
            "Sent nonces for signature id {:?} in nonce_aggregator",
            siginfo.signature_id
        );
    }

    if total_sigs == 0 {
        tracing::warn!("Sighash stream returned 0 signatures");
    }
    // Finally, aggregate nonces for the movetx signature
    let pub_nonces = try_join_all(nonce_streams.iter_mut().map(|s| async {
        s.next()
            .await
            .transpose()? // Return the inner error if it exists
            .ok_or_else(|| -> eyre::Report {
                AggregatorError::InputStreamEndedEarlyUnknownSize {
                    // Return an early end error if the stream is empty
                    stream_name: "Nonce stream".to_string(),
                }
                .into()
            })
    }))
    .await
    .wrap_err("Failed to aggregate nonces for the move tx")?;

    tracing::debug!("Received nonces for movetx in nonce_aggregator");

    // TODO: consider spawn_blocking here
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
    let mut sig_count = 0;
    while let Some(queue_item) = agg_nonce_receiver.recv().await {
        sig_count += 1;

        tracing::debug!(
            "Received aggregated nonce {} in nonce_distributor",
            sig_count
        );

        let agg_nonce_wrapped = clementine::VerifierDepositSignParams {
            params: Some(clementine::verifier_deposit_sign_params::Params::AggNonce(
                queue_item.agg_nonce.serialize().to_vec(),
            )),
        };

        // Broadcast aggregated nonce to all streams
        try_join_all(
            partial_sig_streams
                .iter_mut()
                .enumerate()
                .map(|(idx, (_, tx))| {
                    let agg_nonce_wrapped = agg_nonce_wrapped.clone();
                    async move {
                        tx.send(agg_nonce_wrapped).await.wrap_err_with(|| {
                            AggregatorError::OutputStreamEndedEarly {
                                stream_name: format!("Partial sig stream {idx}"),
                            }
                        })
                    }
                }),
        )
        .await
        .wrap_err("Failed to send aggregated nonces to verifiers")?;

        tracing::debug!(
            "Sent aggregated nonce {} to verifiers in nonce_distributor",
            sig_count
        );

        let partial_sigs = try_join_all(partial_sig_streams.iter_mut().enumerate().map(
            |(idx, (stream, _))| async move {
                let partial_sig = stream
                    .message()
                    .await
                    .wrap_err_with(|| AggregatorError::RequestFailed {
                        request_name: format!("Partial sig stream {idx}"),
                    })?
                    .ok_or_eyre(AggregatorError::InputStreamEndedEarlyUnknownSize {
                        stream_name: format!("Partial sig stream {idx}"),
                    })?;

                Ok::<_, BridgeError>(
                    MusigPartialSignature::from_slice(&partial_sig.partial_sig)
                        .wrap_err("Failed to parse partial signature")?,
                )
            },
        ))
        .await?;

        tracing::debug!(
            "Received partial signature {} from verifiers in nonce_distributor",
            sig_count
        );

        partial_sig_sender
            .send((partial_sigs, queue_item))
            .await
            .map_err(|_| {
                eyre::eyre!(AggregatorError::OutputStreamEndedEarly {
                    stream_name: "partial_sig_sender".into(),
                })
            })?;

        tracing::debug!(
            "Sent partial signature {} to signature_aggregator in nonce_distributor",
            sig_count
        );
    }

    Ok(())
}

/// Collects partial signatures from given stream and aggregates them.
async fn signature_aggregator(
    mut partial_sig_receiver: Receiver<(Vec<MusigPartialSignature>, AggNonceQueueItem)>,
    verifiers_public_keys: Vec<PublicKey>,
    final_sig_sender: Sender<FinalSigQueueItem>,
) -> Result<(), BridgeError> {
    let mut sig_count = 0;
    while let Some((partial_sigs, queue_item)) = partial_sig_receiver.recv().await {
        sig_count += 1;
        tracing::debug!(
            "Received partial signatures {} in signature_aggregator",
            sig_count
        );

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
            .wrap_err_with(|| {
                eyre::eyre!(AggregatorError::OutputStreamEndedEarly {
                    stream_name: "final_sig_sender".into(),
                })
            })?;
        tracing::debug!(
            "Sent aggregated signature {} to signature_distributor in signature_aggregator",
            sig_count
        );
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
    let mut sig_count = 0;
    while let Some(queue_item) = final_sig_receiver.recv().await {
        sig_count += 1;
        tracing::debug!("Received signature {} in signature_distributor", sig_count);
        let final_params = VerifierDepositFinalizeParams {
            params: Some(Params::SchnorrSig(queue_item.final_sig)),
        };

        // TODO: consider the waiting of each verifier here.
        try_join_all(deposit_finalize_sender.iter().map(|tx| {
            let final_params = final_params.clone();
            async move {
                tx.send(final_params).await.wrap_err_with(|| {
                    AggregatorError::OutputStreamEndedEarly {
                        stream_name: "Deposit finalize sender".to_string(),
                    }
                })
            }
        }))
        .await
        .wrap_err("Failed to send final signatures to verifiers")?;

        tracing::debug!(
            "Sent signature {} to verifiers in signature_distributor",
            sig_count
        );
    }

    let movetx_agg_nonce = movetx_agg_nonce
        .await
        .wrap_err("Failed to get movetx aggregated nonce")?;

    tracing::debug!("Got movetx aggregated nonce in signature distributor");

    // Send the movetx agg nonce to the verifiers.
    for tx in &deposit_finalize_sender {
        tx.send(VerifierDepositFinalizeParams {
            params: Some(Params::MoveTxAggNonce(
                movetx_agg_nonce.serialize().to_vec(),
            )),
        })
        .await
        .wrap_err_with(|| AggregatorError::OutputStreamEndedEarly {
            stream_name: "Deposit finalize sender (for movetx agg nonce)".to_string(),
        })?;
    }
    tracing::debug!("Sent movetx aggregated nonce to verifiers in signature distributor");

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
    let mut nonce_streams = try_join_all(verifier_clients.into_iter().enumerate().map(
        |(idx, client)| {
            let mut client = client.clone();

            async move {
                let response_stream = client
                    .nonce_gen(tonic::Request::new(clementine::NonceGenRequest {
                        num_nonces,
                    }))
                    .await
                    .wrap_err_with(|| AggregatorError::RequestFailed {
                        request_name: format!("Nonce gen stream for verifier {idx}"),
                    })?;

                Ok::<_, BridgeError>(response_stream.into_inner())
            }
        },
    ))
    .await?;

    // Get the first responses from verifiers.
    let first_responses: Vec<clementine::NonceGenFirstResponse> = try_join_all(
        nonce_streams
            .iter_mut()
            .enumerate()
            .map(|(idx, stream)| async move {
                parser::verifier::parse_nonce_gen_first_response(stream)
                    .await
                    .wrap_err_with(|| format!("Failed to get initial response from verifier {idx}"))
            }),
    )
    .await
    .wrap_err("Failed to get nonce gen's initial responses from verifiers")?;

    let transformed_streams = nonce_streams
        .into_iter()
        .enumerate()
        .map(|(idx, stream)| {
            stream
                .map(move |result| {
                    Aggregator::extract_pub_nonce(
                        result
                            .wrap_err_with(|| AggregatorError::InputStreamEndedEarlyUnknownSize {
                                stream_name: format!("Nonce gen stream for verifier {idx}"),
                            })?
                            .response,
                    )
                })
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
                break Err(Status::internal(format!(
                    "lost {n} items due to lagging receiver"
                )));
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
        match response.ok_or_eyre("NonceGen response is empty")? {
            clementine::nonce_gen_response::Response::PubNonce(pub_nonce) => {
                Ok(MusigPubNonce::from_slice(&pub_nonce).wrap_err("Failed to parse pub nonce")?)
            }
            _ => Err(eyre::eyre!("Expected PubNonce in response").into()),
        }
    }

    /// For a specific deposit, collects needed signatures from all operators into a [`Vec<Vec<Signature>>`].
    async fn collect_operator_sigs(
        operator_clients: Vec<ClementineOperatorClient<tonic::transport::Channel>>,
        config: BridgeConfig,
        mut deposit_sign_session: DepositSignSession,
    ) -> Result<Vec<Vec<Signature>>, BridgeError> {
        deposit_sign_session.nonce_gen_first_responses = Vec::new(); // not needed for operators
        let mut operator_sigs_streams =
            // create deposit sign streams with each operator
            try_join_all(operator_clients.into_iter().enumerate().map(|(idx, mut operator_client)| {
                let sign_session = deposit_sign_session.clone();
                async move {
                    let stream = operator_client
                        .deposit_sign(tonic::Request::new(sign_session))
                        .await.wrap_err_with(|| AggregatorError::RequestFailed {
                            request_name: format!("Deposit sign stream for operator {idx}"),
                        })?;
                    Ok::<_, BridgeError>(stream.into_inner())
                }
            }))
                .await?;

        let deposit_data: DepositData = deposit_sign_session
            .deposit_params
            .clone()
            .ok_or_else(|| eyre::eyre!("No deposit params found in deposit sign session"))?
            .try_into()?;

        // calculate number of signatures needed from each operator
        let needed_sigs = config.get_num_required_operator_sigs(&deposit_data);

        // get signatures from each operator's signature streams
        let operator_sigs = try_join_all(operator_sigs_streams.iter_mut().enumerate().map(
            |(idx, stream)| async move {
                let mut sigs: Vec<Signature> = Vec::with_capacity(needed_sigs);
                while let Some(sig) =
                    stream
                        .message()
                        .await
                        .wrap_err_with(|| AggregatorError::RequestFailed {
                            request_name: format!("Deposit sign stream for operator {idx}"),
                        })?
                {
                    sigs.push(Signature::from_slice(&sig.schnorr_sig).wrap_err_with(|| {
                        format!("Failed to parse Schnorr signature from operator {idx}")
                    })?);
                }
                Ok::<_, BridgeError>(sigs)
            },
        ))
        .await?;

        // check if all signatures are received
        for (idx, sigs) in operator_sigs.iter().enumerate() {
            if sigs.len() != needed_sigs {
                return Err(eyre::eyre!(
                    "Not all operator sigs received from operator {}.\n Expected: {}, got: {}",
                    idx,
                    needed_sigs,
                    sigs.len()
                )
                .into());
            }
        }
        Ok(operator_sigs)
    }

    async fn send_movetx(
        &self,
        partial_sigs: Vec<Vec<u8>>,
        movetx_agg_nonce: MusigAggNonce,
        deposit_params: DepositParams,
    ) -> Result<TxHandler<Signed>, Status> {
        let mut deposit_data: crate::builder::transaction::DepositData =
            deposit_params.try_into()?;
        let musig_partial_sigs = parser::verifier::parse_partial_sigs(partial_sigs)?;

        // create move tx and calculate sighash
        let mut move_txhandler =
            create_move_to_vault_txhandler(&mut deposit_data, self.config.protocol_paramset())?;

        let sighash = move_txhandler.calculate_script_spend_sighash_indexed(
            0,
            0,
            bitcoin::TapSighashType::Default,
        )?;

        // aggregate partial signatures
        let verifiers_public_keys = deposit_data.get_verifiers();
        let final_sig = crate::musig2::aggregate_partial_signatures(
            &verifiers_public_keys,
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

        let mut dbtx = self.db.begin_transaction().await?;
        self.tx_sender
            .insert_try_to_send(
                &mut dbtx,
                Some(TxMetadata {
                    deposit_outpoint: Some(deposit_data.get_deposit_outpoint()),
                    operator_xonly_pk: None,
                    round_idx: None,
                    kickoff_idx: None,
                    tx_type: TransactionType::MoveToVault,
                }),
                move_tx,
                FeePayingType::CPFP,
                &[],
                &[],
                &[],
                &[],
            )
            .await
            .map_err(BridgeError::from)?;
        dbtx.commit()
            .await
            .map_err(|e| Status::internal(format!("Failed to commit db transaction: {}", e)))?;

        // TODO: Sign the transaction correctly after we create taproot witness generation functions
        Ok(move_txhandler.promote()?)
    }

    /// Fetches operator xonly public keys from operators.
    pub async fn collect_operator_xonly_public_keys_with_clients(
        operator_clients: &[ClementineOperatorClient<tonic::transport::Channel>],
    ) -> Result<Vec<XOnlyPublicKey>, BridgeError> {
        tracing::info!("Collecting operator xonly public keys...");

        let operator_xonly_pks = try_join_all(operator_clients.iter().map(|client| {
            let mut client = client.clone();

            async move {
                let response = client
                    .get_x_only_public_key(Request::new(Empty {}))
                    .await?
                    .into_inner();

                XOnlyPublicKey::from_slice(&response.xonly_public_key).map_err(|e| {
                    Status::internal(format!(
                        "Failed to parse operator xonly public key: {:?}",
                        e
                    ))
                })
            }
        }))
        .await
        .wrap_err("Failed to collect operator xonly public keys")?;

        Ok(operator_xonly_pks)
    }

    /// Fetches operator xonly public keys from operators.
    pub async fn collect_operator_xonly_public_keys(
        &self,
    ) -> Result<Vec<XOnlyPublicKey>, BridgeError> {
        Aggregator::collect_operator_xonly_public_keys_with_clients(self.get_operator_clients())
            .await
    }

    pub async fn collect_verifier_public_keys_with_clients(
        verifier_clients: &[ClementineVerifierClient<tonic::transport::Channel>],
    ) -> Result<(Vec<Vec<u8>>, Vec<PublicKey>), BridgeError> {
        tracing::info!("Collecting verifier public keys...");

        let (vpks, verifier_public_keys): (Vec<Vec<u8>>, Vec<PublicKey>) =
            try_join_all(verifier_clients.iter().map(|client| {
                let mut client = client.clone();

                async move {
                    let verifier_params = client
                        .get_params(Request::new(Empty {}))
                        .await?
                        .into_inner();
                    let encoded_verifier_public_key = verifier_params.public_key;
                    let decoded_verifier_public_key =
                        PublicKey::from_slice(&encoded_verifier_public_key).map_err(|e| {
                            Status::internal(format!("Failed to parse public key: {:?}", e))
                        })?;

                    Ok::<_, Status>((encoded_verifier_public_key, decoded_verifier_public_key))
                }
            }))
            .await
            .wrap_err("Failed to collect verifier public keys")?
            .into_iter()
            .unzip();

        Ok((vpks, verifier_public_keys))
    }

    /// Fetches verifier public keys from verifiers and sets up N-of-N.
    pub async fn collect_verifier_public_keys(&self) -> Result<VerifierPublicKeys, BridgeError> {
        let (vpks, _) =
            Aggregator::collect_verifier_public_keys_with_clients(self.get_verifier_clients())
                .await?;

        Ok(VerifierPublicKeys {
            verifier_public_keys: vpks,
        })
    }
}

#[async_trait]
impl ClementineAggregator for Aggregator {
    async fn internal_send_tx(
        &self,
        request: Request<clementine::SendTxRequest>,
    ) -> Result<Response<Empty>, Status> {
        let send_tx_req = request.into_inner();
        let fee_type = send_tx_req.fee_type();
        let signed_tx: bitcoin::Transaction = send_tx_req
            .raw_tx
            .ok_or(Status::invalid_argument("Missing raw_tx"))?
            .try_into()?;
        let mut dbtx = self.db.begin_transaction().await?;
        self.tx_sender
            .insert_try_to_send(
                &mut dbtx,
                None,
                &signed_tx,
                fee_type.try_into()?,
                &[],
                &[],
                &[],
                &[],
            )
            .await
            .map_err(BridgeError::from)?;
        dbtx.commit()
            .await
            .map_err(|e| Status::internal(format!("Failed to commit db transaction: {}", e)))?;
        Ok(Response::new(Empty {}))
    }

    #[tracing::instrument(skip_all, err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn setup(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<VerifierPublicKeys>, Status> {
        let verifier_public_keys = self.collect_verifier_public_keys().await?;
        let _ = self.collect_operator_xonly_public_keys().await?;

        tracing::debug!(
            "Verifier public keys: {:?}",
            verifier_public_keys.verifier_public_keys
        );

        // Propagate Operators configurations to all verifier clients
        const CHANNEL_CAPACITY: usize = 1024 * 16;
        let (operator_params_tx, operator_params_rx) =
            tokio::sync::broadcast::channel(CHANNEL_CAPACITY);
        let operator_params_rx_handles = (0..self.get_verifier_clients().len())
            .map(|_| operator_params_rx.resubscribe())
            .collect::<Vec<_>>();

        let operators = self.get_operator_clients().to_vec();
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

        let verifiers = self.get_verifier_clients().to_vec();
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

        try_join_all([
            get_operator_params_chunked_handle,
            set_operator_params_handle,
        ])
        .await
        .wrap_err("aggregator setup failed")
        .map_err(BridgeError::from)?
        .into_iter()
        .collect::<Result<Vec<_>, Status>>()?;

        Ok(Response::new(verifier_public_keys))
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
        request: Request<Deposit>,
    ) -> Result<Response<clementine::Txid>, Status> {
        let deposit_info: DepositInfo = request.into_inner().try_into()?;

        let deposit_data = DepositData {
            deposit: deposit_info,
            nofn_xonly_pk: None,
            actors: Actors {
                verifiers: self.get_verifier_keys(),
                watchtowers: vec![],
                operators: self.get_operator_keys(),
            },
        };

        let deposit_params = deposit_data.clone().into();

        // Collect and distribute keys needed keys from operators and watchtowers to verifiers
        let start = std::time::Instant::now();
        self.collect_and_distribute_keys(&deposit_params).await?;
        tracing::info!("Collected and distributed keys in {:?}", start.elapsed());

        let participating_verifiers = self.get_participating_verifiers(&deposit_data).await?;

        // Generate nonce streams for all verifiers.
        let num_required_sigs = self.config.get_num_required_nofn_sigs(&deposit_data);
        let (first_responses, nonce_streams) = create_nonce_streams(
            participating_verifiers.clone(),
            num_required_sigs as u32 + 1,
        )
        .await?; // ask for +1 for the final movetx signature, but don't send it on deposit_sign stage

        let mut partial_sig_streams =
            try_join_all(participating_verifiers.iter().map(|verifier_client| {
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
        let deposit_finalize_clients = participating_verifiers.clone();
        let deposit_finalize_streams = try_join_all(deposit_finalize_clients.into_iter().map(
            |mut verifier_client| async move {
                let (tx, rx) = tokio::sync::mpsc::channel(1280);
                let receiver_stream = tokio_stream::wrappers::ReceiverStream::new(rx);
                // start deposit_finalize with tokio spawn
                let deposit_finalize_future =
                    tokio::spawn(
                        async move { verifier_client.deposit_finalize(receiver_stream).await },
                    );

                Ok::<_, Status>((deposit_finalize_future, tx))
            },
        ))
        .await?;

        tracing::info!("Sending deposit finalize streams to verifiers");

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

        let deposit_data: crate::builder::transaction::DepositData =
            deposit_params.clone().try_into()?;

        let deposit_blockhash = self
            .rpc
            .get_blockhash_of_tx(&deposit_data.get_deposit_outpoint().txid)
            .await
            .map_to_status()?;

        let verifiers_public_keys = deposit_data.get_verifiers();

        // Create sighash stream for transaction signing
        let sighash_stream = Box::pin(create_nofn_sighash_stream(
            self.db.clone(),
            self.config.clone(),
            deposit_data.clone(),
            deposit_blockhash,
            false,
        ));

        // Create channels for pipeline communication
        let (agg_nonce_sender, agg_nonce_receiver) = channel(1280);
        let (partial_sig_sender, partial_sig_receiver) = channel(1280);
        let (final_sig_sender, final_sig_receiver) = channel(1280);

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

        tracing::debug!("Getting signatures from operators");
        // Get sigs from each operator in background
        let operator_sigs_fut = tokio::spawn(Aggregator::collect_operator_sigs(
            self.get_participating_operators(&deposit_data).await?,
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

        tracing::debug!("Waiting for pipeline tasks to complete");
        // Wait for all pipeline tasks to complete
        try_join_all([nonce_dist_handle, sig_agg_handle, sig_dist_handle])
            .await
            .map_err(|_| Status::internal("panic when pipelining"))?;

        tracing::debug!("Pipeline tasks completed");

        // Right now we collect all operator sigs then start to send them, we can do it simultaneously in the future
        // Need to change sig verification ordering in deposit_finalize() in verifiers so that we verify
        // 1st signature of all operators, then 2nd of all operators etc.
        let operator_sigs = operator_sigs_fut
            .await
            .map_err(|_| Status::internal("panic when collecting operator signatures"))??;

        tracing::debug!("Got all operator signatures");

        // send operators sigs to verifiers after all verifiers have signed
        let send_operator_sigs: Vec<_> = deposit_finalize_sender
            .iter()
            .map(|tx| async {
                for sigs in operator_sigs.iter() {
                    for sig in sigs.iter() {
                        let deposit_finalize_param: VerifierDepositFinalizeParams = sig.into();

                        tx.send(deposit_finalize_param).await.wrap_err_with(|| {
                            eyre::eyre!(AggregatorError::OutputStreamEndedEarly {
                                stream_name: "deposit_finalize_sender".into(),
                            })
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
        let move_tx_partial_sigs =
            try_join_all(deposit_finalize_futures.iter_mut().map(|fut| async {
                Ok::<_, Status>(
                    fut.await
                        .map_err(|_| Status::internal("panic finishing deposit_finalize"))??
                        .into_inner()
                        .partial_sig,
                )
            }))
            .await
            .map_err(|e| Status::internal(format!("Failed to finalize deposit: {:?}", e)))?;

        tracing::debug!("Received move tx partial sigs: {:?}", move_tx_partial_sigs);

        // Create the final move transaction and check the signatures
        let movetx_agg_nonce = nonce_agg_handle.await?;
        let signed_movetx_handler = self
            .send_movetx(move_tx_partial_sigs, movetx_agg_nonce, deposit_params)
            .await?;
        let txid = *signed_movetx_handler.get_txid();

        Ok(Response::new(txid.into()))
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn withdraw(
        &self,
        request: Request<WithdrawParams>,
    ) -> Result<Response<AggregatorWithdrawResponse>, Status> {
        let withdraw_params = request.into_inner();
        let operators = self.get_operator_clients().to_vec();
        let withdraw_futures = operators.iter().map(|operator| {
            let mut operator = operator.clone();
            let params = withdraw_params.clone();
            async move { operator.withdraw(Request::new(params)).await }
        });

        let responses = futures::future::join_all(withdraw_futures).await;
        Ok(Response::new(AggregatorWithdrawResponse {
            withdraw_responses: responses
                .into_iter()
                .map(|r| clementine::WithdrawResult {
                    result: Some(match r {
                        Ok(response) => {
                            clementine::withdraw_result::Result::Success(response.into_inner())
                        }
                        Err(e) => clementine::withdraw_result::Result::Error(
                            clementine::WithdrawErrorResponse {
                                error: e.to_string(),
                            },
                        ),
                    }),
                })
                .collect(),
        }))
    }

    async fn get_nofn_aggregated_xonly_pk(
        &self,
        _: tonic::Request<super::Empty>,
    ) -> std::result::Result<tonic::Response<super::NofnResponse>, tonic::Status> {
        let verifier_keys = self.get_verifier_keys();
        let num_verifiers = verifier_keys.len();
        let nofn_xonly_pk = bitcoin::XOnlyPublicKey::from_musig2_pks(verifier_keys, None)
            .expect("Failed to aggregate verifier public keys");
        Ok(Response::new(super::NofnResponse {
            nofn_xonly_pk: nofn_xonly_pk.serialize().to_vec(),
            num_verifiers: num_verifiers as u32,
        }))
    }
}

#[cfg(test)]
mod tests {
    use crate::actor::Actor;
    use crate::builder::transaction::{BaseDepositData, DepositInfo, DepositType};
    use crate::citrea::mock::MockCitreaClient;
    use crate::musig2::AggregateFromPublicKeys;
    use crate::rpc::clementine::{self};
    use crate::test::common::*;
    use crate::{builder, EVMAddress};
    use bitcoin::Txid;
    use bitcoincore_rpc::RpcApi;
    use eyre::Context;
    use std::time::Duration;
    use tokio::time::sleep;

    #[tokio::test]
    async fn aggregator_double_setup_fail() {
        let mut config = create_test_config_with_thread_name().await;
        let _regtest = create_regtest_rpc(&mut config).await;

        let (_, _, mut aggregator, _cleanup) = create_actors::<MockCitreaClient>(&config).await;

        aggregator
            .setup(tonic::Request::new(clementine::Empty {}))
            .await
            .unwrap();

        assert!(aggregator
            .setup(tonic::Request::new(clementine::Empty {}))
            .await
            .is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn aggregator_deposit_movetx_lands_onchain() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc();
        let (_verifiers, _operators, mut aggregator, _cleanup) =
            create_actors::<MockCitreaClient>(&config).await;

        let evm_address = EVMAddress([1u8; 20]);
        let signer = Actor::new(
            config.secret_key,
            config.winternitz_secret_key,
            config.protocol_paramset().network,
        );

        let verifiers_public_keys: Vec<bitcoin::secp256k1::PublicKey> = aggregator
            .setup(tonic::Request::new(clementine::Empty {}))
            .await
            .unwrap()
            .into_inner()
            .try_into()
            .unwrap();
        sleep(Duration::from_secs(3)).await;

        let nofn_xonly_pk =
            bitcoin::XOnlyPublicKey::from_musig2_pks(verifiers_public_keys.clone(), None).unwrap();

        let deposit_address = builder::address::generate_deposit_address(
            nofn_xonly_pk,
            signer.address.as_unchecked(),
            evm_address,
            config.protocol_paramset().bridge_amount,
            config.protocol_paramset().network,
            config.protocol_paramset().user_takes_after,
        )
        .unwrap()
        .0;

        let deposit_outpoint = rpc
            .send_to_address(&deposit_address, config.protocol_paramset().bridge_amount)
            .await
            .unwrap();
        rpc.mine_blocks(18).await.unwrap();

        let deposit_info = DepositInfo {
            deposit_outpoint,
            deposit_type: DepositType::BaseDeposit(BaseDepositData {
                evm_address,
                recovery_taproot_address: signer.address.as_unchecked().clone(),
            }),
        };

        let movetx_txid: Txid = aggregator
            .new_deposit(clementine::Deposit::from(deposit_info))
            .await
            .unwrap()
            .into_inner()
            .try_into()
            .unwrap();
        rpc.mine_blocks(1).await.unwrap();
        sleep(Duration::from_secs(3)).await;

        let tx = poll_get(
            async || {
                rpc.mine_blocks(1).await.unwrap();

                let tx_result = rpc
                    .client
                    .get_raw_transaction_info(&movetx_txid, None)
                    .await;

                let tx_result = tx_result
                    .inspect_err(|e| {
                        tracing::error!("Error getting transaction: {:?}", e);
                    })
                    .ok();

                Ok(tx_result)
            },
            None,
            None,
        )
        .await
        .wrap_err_with(|| eyre::eyre!("MoveTx did not land onchain"))
        .unwrap();

        assert!(tx.confirmations.unwrap() > 0);
    }
}
