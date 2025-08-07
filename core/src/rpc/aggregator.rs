use super::clementine::{
    clementine_aggregator_server::ClementineAggregator, verifier_deposit_finalize_params,
    DepositParams, Empty, VerifierDepositFinalizeParams,
};
use super::clementine::{
    AggregatorWithdrawResponse, Deposit, EntityStatuses, GetEntityStatusesRequest,
    OptimisticPayoutParams, RawSignedTx, VergenResponse, VerifierPublicKeys,
};
use crate::aggregator::{AggregatorServer, ParticipatingOperators, ParticipatingVerifiers};
use crate::bitvm_client::SECP;
use crate::builder::sighash::SignatureInfo;
use crate::builder::transaction::{
    create_emergency_stop_txhandler, create_move_to_vault_txhandler,
    create_optimistic_payout_txhandler, Signed, TransactionType, TxHandler,
};
use crate::config::BridgeConfig;
use crate::constants::{
    DEPOSIT_FINALIZATION_TIMEOUT, DEPOSIT_FINALIZE_STREAM_CREATION_TIMEOUT,
    KEY_DISTRIBUTION_TIMEOUT, NONCE_STREAM_CREATION_TIMEOUT, OPERATOR_SIGS_STREAM_CREATION_TIMEOUT,
    OPERATOR_SIGS_TIMEOUT, OVERALL_DEPOSIT_TIMEOUT, PARTIAL_SIG_STREAM_CREATION_TIMEOUT,
    PIPELINE_COMPLETION_TIMEOUT, SEND_OPERATOR_SIGS_TIMEOUT, WITHDRAWAL_TIMEOUT,
};
use crate::deposit::{Actors, DepositData, DepositInfo};
use crate::errors::ResultExt;
use crate::musig2::AggregateFromPublicKeys;
use crate::rpc::clementine::{AggregatorWithdrawalInput, VerifierDepositSignParams};
use crate::rpc::parser;
use crate::utils::{get_vergen_response, timed_request, timed_try_join_all, ScriptBufExt};
use crate::utils::{FeePayingType, TxMetadata};
use crate::UTXO;
use crate::{
    aggregator::Aggregator,
    builder::sighash::create_nofn_sighash_stream,
    errors::BridgeError,
    musig2::aggregate_nonces,
    rpc::clementine::{self, DepositSignSession},
};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::schnorr::{self, Signature};
use bitcoin::secp256k1::{Message, PublicKey};
use bitcoin::{TapSighash, TxOut, Txid, XOnlyPublicKey};
use eyre::{Context, OptionExt};
use futures::{
    future::try_join_all,
    stream::{BoxStream, TryStreamExt},
    FutureExt, Stream, StreamExt, TryFutureExt,
};
use secp256k1::musig::{AggregatedNonce, PartialSignature, PublicNonce};
use std::future::Future;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tonic::{async_trait, Request, Response, Status, Streaming};

struct AggNonceQueueItem {
    agg_nonce: AggregatedNonce,
    sighash: TapSighash,
}

#[derive(Debug, Clone)]
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

async fn get_next_pub_nonces(
    nonce_streams: &mut [impl Stream<Item = Result<PublicNonce, BridgeError>>
              + Unpin
              + Send
              + 'static],
) -> Result<Vec<PublicNonce>, BridgeError> {
    Ok(try_join_all(
        nonce_streams
            .iter_mut()
            .enumerate()
            .map(|(i, s)| async move {
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
            }),
    )
    .await?)
}

/// For each expected sighash, we collect a batch of public nonces from all verifiers. We aggregate and send to the agg_nonce_sender. Then repeat for the next sighash.
async fn nonce_aggregator(
    mut nonce_streams: Vec<
        impl Stream<Item = Result<PublicNonce, BridgeError>> + Unpin + Send + 'static,
    >,
    mut sighash_stream: impl Stream<Item = Result<(TapSighash, SignatureInfo), BridgeError>>
        + Unpin
        + Send
        + 'static,
    agg_nonce_sender: Sender<AggNonceQueueItem>,
) -> Result<(AggregatedNonce, AggregatedNonce), BridgeError> {
    let mut total_sigs = 0;

    tracing::info!("Starting nonce aggregation");

    // We assume the sighash stream returns the correct number of items.
    while let Some(msg) = sighash_stream.next().await {
        let (sighash, siginfo) = msg.wrap_err("Sighash stream failed")?;

        total_sigs += 1;

        let pub_nonces = get_next_pub_nonces(&mut nonce_streams)
            .await
            .wrap_err_with(|| {
                format!("Failed to aggregate nonces for sighash with info: {siginfo:?}")
            })?;

        tracing::trace!(
            "Received nonces for signature id {:?} in nonce_aggregator",
            siginfo.signature_id
        );

        let agg_nonce = aggregate_nonces(pub_nonces.iter().collect::<Vec<_>>().as_slice())?;

        agg_nonce_sender
            .send(AggNonceQueueItem { agg_nonce, sighash })
            .await
            .wrap_err_with(|| AggregatorError::OutputStreamEndedEarly {
                stream_name: "nonce_aggregator".to_string(),
            })?;

        tracing::trace!(
            "Sent nonces for signature id {:?} in nonce_aggregator",
            siginfo.signature_id
        );
    }

    if total_sigs == 0 {
        tracing::warn!("Sighash stream returned 0 signatures");
    }
    // aggregate nonces for the movetx signature
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

    tracing::trace!("Received nonces for movetx in nonce_aggregator");

    let move_tx_agg_nonce = aggregate_nonces(pub_nonces.iter().collect::<Vec<_>>().as_slice())?;

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
    .wrap_err("Failed to aggregate nonces for the emergency stop tx")?;

    let emergency_stop_agg_nonce =
        aggregate_nonces(pub_nonces.iter().collect::<Vec<_>>().as_slice())?;

    Ok((move_tx_agg_nonce, emergency_stop_agg_nonce))
}

/// Reroutes aggregated nonces to the signature aggregator.
async fn nonce_distributor(
    mut agg_nonce_receiver: Receiver<AggNonceQueueItem>,
    partial_sig_streams: Vec<(
        Streaming<clementine::PartialSig>,
        Sender<clementine::VerifierDepositSignParams>,
    )>,
    partial_sig_sender: Sender<(Vec<PartialSignature>, AggNonceQueueItem)>,
) -> Result<(), BridgeError> {
    let mut sig_count = 0;
    let (mut partial_sig_rx, mut partial_sig_tx): (Vec<_>, Vec<_>) =
        partial_sig_streams.into_iter().unzip();

    let (queue_tx, mut queue_rx) = channel(crate::constants::DEFAULT_CHANNEL_SIZE);

    let handle_1 = tokio::spawn(async move {
        while let Some(queue_item) = agg_nonce_receiver.recv().await {
            sig_count += 1;

            tracing::trace!(
                "Received aggregated nonce {} in nonce_distributor",
                sig_count
            );

            let agg_nonce_wrapped = clementine::VerifierDepositSignParams {
                params: Some(clementine::verifier_deposit_sign_params::Params::AggNonce(
                    queue_item.agg_nonce.serialize().to_vec(),
                )),
            };

            // Broadcast aggregated nonce to all streams
            try_join_all(partial_sig_tx.iter_mut().enumerate().map(|(idx, tx)| {
                let agg_nonce_wrapped = agg_nonce_wrapped.clone();
                async move {
                    tx.send(agg_nonce_wrapped).await.wrap_err_with(|| {
                        AggregatorError::OutputStreamEndedEarly {
                            stream_name: format!("Partial sig stream {idx}"),
                        }
                    })
                }
            }))
            .await
            .wrap_err("Failed to send aggregated nonces to verifiers")?;

            queue_tx
                .send(queue_item)
                .await
                .wrap_err("Other end of channel closed")?;

            tracing::trace!(
                "Sent aggregated nonce {} to verifiers in nonce_distributor",
                sig_count
            );
        }

        Ok::<(), BridgeError>(())
    });

    let handle_2 = tokio::spawn(async move {
        while let Some(queue_item) = queue_rx.recv().await {
            let partial_sigs = try_join_all(partial_sig_rx.iter_mut().enumerate().map(
                |(idx, stream)| async move {
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
                        PartialSignature::from_byte_array(
                            &partial_sig
                                .partial_sig
                                .as_slice()
                                .try_into()
                                .wrap_err("PartialSignature must be 32 bytes")?,
                        )
                        .wrap_err("Failed to parse partial signature")?,
                    )
                },
            ))
            .await?;

            tracing::trace!(
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

            tracing::trace!(
                "Sent partial signature {} to signature_aggregator in nonce_distributor",
                sig_count
            );
        }
        Ok::<(), BridgeError>(())
    });

    let (result_1, result_2) = tokio::join!(handle_1, handle_2);

    result_1
        .wrap_err("Task crashed while distributing aggnonces")?
        .wrap_err("Error while distributing aggnonces")?;
    result_2
        .wrap_err("Task crashed while receiving partial sigs")?
        .wrap_err("Error while receiving partial sigs")?;

    Ok(())
}

/// Collects partial signatures from given stream and aggregates them.
async fn signature_aggregator(
    mut partial_sig_receiver: Receiver<(Vec<PartialSignature>, AggNonceQueueItem)>,
    verifiers_public_keys: Vec<PublicKey>,
    final_sig_sender: Sender<FinalSigQueueItem>,
) -> Result<(), BridgeError> {
    let mut sig_count = 0;
    while let Some((partial_sigs, queue_item)) = partial_sig_receiver.recv().await {
        sig_count += 1;
        tracing::trace!(
            "Received partial signatures {} in signature_aggregator",
            sig_count
        );

        let final_sig = crate::musig2::aggregate_partial_signatures(
            verifiers_public_keys.clone(),
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
        tracing::trace!(
            "Sent aggregated signature {} to signature_distributor in signature_aggregator",
            sig_count
        );
    }

    Ok(())
}

/// Reroutes aggregated signatures to the caller.
/// Also sends 2 aggregated nonces to the verifiers.
async fn signature_distributor(
    mut final_sig_receiver: Receiver<FinalSigQueueItem>,
    deposit_finalize_sender: Vec<Sender<VerifierDepositFinalizeParams>>,
    agg_nonce: impl Future<Output = Result<(AggregatedNonce, AggregatedNonce), Status>>,
) -> Result<(), BridgeError> {
    use verifier_deposit_finalize_params::Params;
    let mut sig_count = 0;
    while let Some(queue_item) = final_sig_receiver.recv().await {
        sig_count += 1;
        tracing::trace!("Received signature {} in signature_distributor", sig_count);
        let final_params = VerifierDepositFinalizeParams {
            params: Some(Params::SchnorrSig(queue_item.final_sig)),
        };

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

        tracing::trace!(
            "Sent signature {} to verifiers in signature_distributor",
            sig_count
        );
    }

    let (movetx_agg_nonce, emergency_stop_agg_nonce) = agg_nonce
        .await
        .wrap_err("Failed to get aggregated nonce for movetx and emergency stop")?;

    tracing::info!("Got aggregated nonce for movetx and emergency stop in signature distributor");

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
    tracing::info!("Sent movetx aggregated nonce to verifiers in signature distributor");

    // send emergency stop agg nonce to verifiers
    for tx in &deposit_finalize_sender {
        tx.send(VerifierDepositFinalizeParams {
            params: Some(Params::EmergencyStopAggNonce(
                emergency_stop_agg_nonce.serialize().to_vec(),
            )),
        })
        .await
        .wrap_err_with(|| AggregatorError::OutputStreamEndedEarly {
            stream_name: "Deposit finalize sender (for emergency stop agg nonce)".to_string(),
        })?;
    }
    tracing::info!("Sent emergency stop aggregated nonce to verifiers in signature distributor");

    Ok(())
}

/// Creates a stream of nonces from verifiers.
/// This will automatically get the first response from the verifiers.
///
/// # Returns
///
/// - Vec<[`clementine::NonceGenFirstResponse`]>: First response from each verifier
/// - Vec<BoxStream<Result<[`PublicNonce`], BridgeError>>>: Stream of nonces from each verifier
async fn create_nonce_streams(
    verifiers: ParticipatingVerifiers,
    num_nonces: u32,
    #[cfg(test)] config: &crate::config::BridgeConfig,
) -> Result<
    (
        Vec<clementine::NonceGenFirstResponse>,
        Vec<BoxStream<'static, Result<PublicNonce, BridgeError>>>,
    ),
    BridgeError,
> {
    let mut nonce_streams = timed_try_join_all(
        NONCE_STREAM_CREATION_TIMEOUT,
        "Nonce stream creation",
        Some(verifiers.ids()),
        verifiers
            .clients()
            .into_iter()
            .enumerate()
            .map(|(idx, client)| {
                let mut client = client.clone();
                #[cfg(test)]
                let config = config.clone();

                async move {
                    #[cfg(test)]
                    config
                        .test_params
                        .timeout_params
                        .hook_timeout_nonce_stream_creation_verifier(idx)
                        .await;
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
            }),
    )
    .await?;

    // Get the first responses from verifiers.
    let first_responses: Vec<clementine::NonceGenFirstResponse> =
        try_join_all(nonce_streams.iter_mut().zip(verifiers.ids()).map(
            |(stream, id)| async move {
                parser::verifier::parse_nonce_gen_first_response(stream)
                    .await
                    .wrap_err_with(|| format!("Failed to get initial response from {id}"))
            },
        ))
        .await
        .wrap_err("Failed to get nonce gen's initial responses from verifiers")?;

    let transformed_streams = nonce_streams
        .into_iter()
        .zip(verifiers.ids())
        .map(|(stream, id)| {
            stream
                .map(move |result| {
                    Aggregator::extract_pub_nonce(
                        result
                            .wrap_err_with(|| AggregatorError::InputStreamEndedEarlyUnknownSize {
                                stream_name: format!("Nonce gen stream for {id}"),
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
    ) -> Result<PublicNonce, BridgeError> {
        match response.ok_or_eyre("NonceGen response is empty")? {
            clementine::nonce_gen_response::Response::PubNonce(pub_nonce) => {
                Ok(PublicNonce::from_byte_array(
                    &pub_nonce
                        .as_slice()
                        .try_into()
                        .wrap_err("PubNonce must be 66 bytes")?,
                )
                .wrap_err("Failed to parse pub nonce")?)
            }
            _ => Err(eyre::eyre!("Expected PubNonce in response").into()),
        }
    }

    /// For a specific deposit, collects needed signatures from all operators into a [`Vec<Vec<Signature>>`].
    async fn collect_operator_sigs(
        operator_clients: ParticipatingOperators,
        config: BridgeConfig,
        mut deposit_sign_session: DepositSignSession,
    ) -> Result<Vec<Vec<Signature>>, BridgeError> {
        deposit_sign_session.nonce_gen_first_responses = Vec::new(); // not needed for operators
        let mut operator_sigs_streams =
            // create deposit sign streams with each operator
            timed_try_join_all(
                OPERATOR_SIGS_STREAM_CREATION_TIMEOUT,
                "Operator signature stream creation",
                Some(operator_clients.ids()),
                operator_clients.clients().into_iter().enumerate().map(|(idx, mut operator_client)| {
                let sign_session = deposit_sign_session.clone();
                #[cfg(test)]
                let config = config.clone();
                async move {
                    #[cfg(test)]
                    config
                        .test_params
                        .timeout_params
                        .hook_timeout_operator_sig_collection_operator(idx)
                        .await;
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
            .try_into()
            .wrap_err("Failed to convert deposit params to deposit data")?;

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

    async fn create_movetx(
        &self,
        partial_sigs: Vec<Vec<u8>>,
        movetx_agg_nonce: AggregatedNonce,
        deposit_params: DepositParams,
    ) -> Result<TxHandler<Signed>, Status> {
        let mut deposit_data: DepositData = deposit_params.try_into()?;
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
            verifiers_public_keys,
            None,
            movetx_agg_nonce,
            &musig_partial_sigs,
            Message::from_digest(sighash.to_byte_array()),
        )?;

        // Put the signature in the tx
        move_txhandler.set_p2tr_script_spend_witness(&[final_sig.as_ref()], 0, 0)?;

        Ok(move_txhandler.promote()?)
    }

    async fn verify_and_save_emergency_stop_sigs(
        &self,
        emergency_stop_sigs: Vec<Vec<u8>>,
        emergency_stop_agg_nonce: AggregatedNonce,
        deposit_params: DepositParams,
    ) -> Result<(), BridgeError> {
        let mut deposit_data: DepositData = deposit_params
            .try_into()
            .wrap_err("Failed to convert deposit params to deposit data")?;
        let musig_partial_sigs = parser::verifier::parse_partial_sigs(emergency_stop_sigs)
            .wrap_err("Failed to parse emergency stop signatures")?;

        // create move tx and calculate sighash
        let move_txhandler =
            create_move_to_vault_txhandler(&mut deposit_data, self.config.protocol_paramset())?;

        let mut emergency_stop_txhandler = create_emergency_stop_txhandler(
            &mut deposit_data,
            &move_txhandler,
            self.config.protocol_paramset(),
        )?;

        let sighash = emergency_stop_txhandler.calculate_script_spend_sighash_indexed(
            0,
            0,
            bitcoin::TapSighashType::SinglePlusAnyoneCanPay,
        )?;

        let verifiers_public_keys = deposit_data.get_verifiers();

        let final_sig = crate::musig2::aggregate_partial_signatures(
            verifiers_public_keys,
            None,
            emergency_stop_agg_nonce,
            &musig_partial_sigs,
            Message::from_digest(sighash.to_byte_array()),
        )
        .wrap_err("Failed to aggregate emergency stop signatures")?;

        let final_sig = bitcoin::taproot::Signature {
            signature: final_sig,
            sighash_type: bitcoin::TapSighashType::SinglePlusAnyoneCanPay,
        };

        // insert the signature into the tx
        emergency_stop_txhandler.set_p2tr_script_spend_witness(&[final_sig.serialize()], 0, 0)?;

        let emergency_stop_tx = emergency_stop_txhandler.get_cached_tx();
        let move_to_vault_txid = move_txhandler.get_txid();

        tracing::debug!("Move to vault tx id: {}", move_to_vault_txid.to_string());

        let emergency_stop_pubkey = self
            .config
            .emergency_stop_encryption_public_key
            .ok_or_else(|| eyre::eyre!("Emergency stop encryption public key is not set"))?;
        let encrypted_emergency_stop_tx = crate::encryption::encrypt_bytes(
            emergency_stop_pubkey,
            &bitcoin::consensus::serialize(&emergency_stop_tx),
        )?;

        self.db
            .set_signed_emergency_stop_tx(None, move_to_vault_txid, &encrypted_emergency_stop_tx)
            .await?;

        Ok(())
    }

    #[cfg(feature = "automation")]
    pub async fn send_emergency_stop_tx(
        &self,
        tx: bitcoin::Transaction,
    ) -> Result<bitcoin::Transaction, Status> {
        // Add fee bumper.
        let mut dbtx = self.db.begin_transaction().await?;
        self.tx_sender
            .insert_try_to_send(
                &mut dbtx,
                Some(TxMetadata {
                    deposit_outpoint: None,
                    operator_xonly_pk: None,
                    round_idx: None,
                    kickoff_idx: None,
                    tx_type: TransactionType::EmergencyStop,
                }),
                &tx,
                FeePayingType::RBF,
                None,
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

        Ok(tx)
    }
}

#[async_trait]
impl ClementineAggregator for AggregatorServer {
    async fn vergen(&self, _request: Request<Empty>) -> Result<Response<VergenResponse>, Status> {
        Ok(Response::new(get_vergen_response()))
    }

    async fn get_entity_statuses(
        &self,
        request: Request<GetEntityStatusesRequest>,
    ) -> Result<Response<EntityStatuses>, Status> {
        let request = request.into_inner();
        let restart_tasks = request.restart_tasks;

        Ok(Response::new(EntityStatuses {
            entity_statuses: self.aggregator.get_entity_statuses(restart_tasks).await?,
        }))
    }

    async fn optimistic_payout(
        &self,
        request: tonic::Request<super::OptimisticWithdrawParams>,
    ) -> std::result::Result<tonic::Response<super::RawSignedTx>, tonic::Status> {
        let opt_withdraw_params = request.into_inner();

        let withdraw_params =
            opt_withdraw_params
                .withdrawal
                .clone()
                .ok_or(Status::invalid_argument(
                    "Withdrawal params not found for optimistic payout",
                ))?;
        let (deposit_id, input_signature, input_outpoint, output_script_pubkey, output_amount) =
            parser::operator::parse_withdrawal_sig_params(withdraw_params)?;

        // if the withdrawal utxo is spent, no reason to sign optimistic payout
        if self
            .rpc
            .is_utxo_spent(&input_outpoint)
            .await
            .map_to_status()?
        {
            return Err(Status::invalid_argument(format!(
                "Withdrawal utxo is already spent: {:?}",
                input_outpoint
            )));
        }

        // get which deposit the withdrawal belongs to
        let withdrawal = self
            .db
            .get_move_to_vault_txid_from_citrea_deposit(None, deposit_id)
            .await?;
        if let Some(move_txid) = withdrawal {
            // check if withdrawal utxo is correct
            let withdrawal_utxo = self
                .db
                .get_withdrawal_utxo_from_citrea_withdrawal(None, deposit_id)
                .await?;
            if withdrawal_utxo != input_outpoint {
                return Err(Status::invalid_argument(format!(
                    "Withdrawal utxo is not correct: {:?} != {:?}",
                    withdrawal_utxo, input_outpoint
                )));
            }

            // Prepare input and output of the payout transaction.
            let withdrawal_prevout = self
                .rpc
                .get_txout_from_outpoint(&input_outpoint)
                .await
                .map_to_status()?;

            let user_xonly_pk = withdrawal_prevout
                .script_pubkey
                .try_get_taproot_pk()
                .map_err(|_| {
                    Status::invalid_argument(format!(
                        "Withdrawal prevout script_pubkey is not a Taproot output: {:?}",
                        withdrawal_prevout.script_pubkey
                    ))
                })?;

            let withdrawal_utxo = UTXO {
                outpoint: input_outpoint,
                txout: withdrawal_prevout,
            };

            let output_txout = TxOut {
                value: output_amount,
                script_pubkey: output_script_pubkey,
            };

            let deposit_data = self
                .db
                .get_deposit_data_with_move_tx(None, move_txid)
                .await?;

            let mut deposit_data = deposit_data
                .ok_or(eyre::eyre!(
                    "Deposit data not found for move txid {}",
                    move_txid
                ))
                .map_err(BridgeError::from)?;

            let mut opt_payout_txhandler = create_optimistic_payout_txhandler(
                &mut deposit_data,
                withdrawal_utxo,
                output_txout,
                input_signature,
                self.config.protocol_paramset(),
            )?;

            let sighash = opt_payout_txhandler.calculate_pubkey_spend_sighash(
                0,
                bitcoin::TapSighashType::SinglePlusAnyoneCanPay,
            )?;

            let message = Message::from_digest(sighash.to_byte_array());

            let sig =
                schnorr::Signature::from_slice(&input_signature.serialize()).map_err(|_| {
                    Status::internal("Failed to parse signature from optimistic payout tx witness")
                })?;

            SECP.verify_schnorr(&sig, &message, &user_xonly_pk)
                .map_err(|_| Status::internal("Invalid signature for optimistic payout tx"))?;

            // get which verifiers participated in the deposit to collect the optimistic payout tx signature
            let participating_verifiers = self.get_participating_verifiers(&deposit_data).await?;
            let (first_responses, mut nonce_streams) = {
                create_nonce_streams(
                    participating_verifiers.clone(),
                    1,
                    #[cfg(test)]
                    &self.config,
                )
                .await?
            };
            // collect nonces
            let pub_nonces = get_next_pub_nonces(&mut nonce_streams)
                .await
                .wrap_err("Failed to aggregate nonces for optimistic payout")
                .map_to_status()?;
            let agg_nonce = aggregate_nonces(pub_nonces.iter().collect::<Vec<_>>().as_slice())?;

            let agg_nonce_bytes = agg_nonce.serialize().to_vec();
            // send the agg nonce to the verifiers to sign the optimistic payout tx
            let payout_sigs = participating_verifiers
                .clients()
                .into_iter()
                .zip(first_responses)
                .map(|(client, first_response)| {
                    let mut client = client.clone();
                    let opt_withdraw_params = opt_withdraw_params.clone();
                    {
                        let agg_nonce_serialized = agg_nonce_bytes.clone();
                        async move {
                            client
                                .optimistic_payout_sign(OptimisticPayoutParams {
                                    opt_withdrawal: Some(opt_withdraw_params),
                                    agg_nonce: agg_nonce_serialized,
                                    nonce_gen: Some(first_response),
                                })
                                .await
                        }
                    }
                })
                .collect::<Vec<_>>();

            // txin at index 1 is deposited utxo in movetx
            let sighash = opt_payout_txhandler.calculate_script_spend_sighash_indexed(
                1,
                0,
                bitcoin::TapSighashType::Default,
            )?;

            // calculate final sig
            let payout_sig = try_join_all(payout_sigs).await?;

            let musig_partial_sigs = payout_sig
                .iter()
                .map(|sig| {
                    PartialSignature::from_byte_array(
                        &sig.get_ref()
                            .partial_sig
                            .clone()
                            .try_into()
                            .map_err(|_| secp256k1::musig::ParseError::MalformedArg)?,
                    )
                })
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| Status::internal(format!("Failed to parse partial sig: {:?}", e)))?;

            let final_sig = bitcoin::taproot::Signature {
                signature: crate::musig2::aggregate_partial_signatures(
                    deposit_data.get_verifiers(),
                    None,
                    agg_nonce,
                    &musig_partial_sigs,
                    Message::from_digest(sighash.to_byte_array()),
                )?,
                sighash_type: bitcoin::TapSighashType::Default,
            };

            // set witness and send tx
            opt_payout_txhandler.set_p2tr_script_spend_witness(&[final_sig.serialize()], 1, 0)?;
            let opt_payout_txhandler = opt_payout_txhandler.promote()?;
            let opt_payout_tx = opt_payout_txhandler.get_cached_tx();

            #[cfg(feature = "automation")]
            {
                tracing::info!("Sending optimistic payout tx via tx_sender");

                let mut dbtx = self.db.begin_transaction().await?;
                self.tx_sender
                    .add_tx_to_queue(
                        &mut dbtx,
                        TransactionType::OptimisticPayout,
                        opt_payout_tx,
                        &[],
                        None,
                        &self.config,
                        None,
                    )
                    .await
                    .map_err(BridgeError::from)?;
                dbtx.commit().await.map_err(|e| {
                    Status::internal(format!(
                        "Failed to commit db transaction to send optimistic payout tx: {}",
                        e
                    ))
                })?;
            }

            Ok(Response::new(RawSignedTx::from(opt_payout_tx)))
        } else {
            Err(Status::not_found(format!(
                "Withdrawal with index {} not found.",
                deposit_id
            )))
        }
    }

    async fn internal_send_tx(
        &self,
        request: Request<clementine::SendTxRequest>,
    ) -> Result<Response<Empty>, Status> {
        #[cfg(not(feature = "automation"))]
        {
            Err(Status::unimplemented("Automation is not enabled"))
        }
        #[cfg(feature = "automation")]
        {
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
                    None,
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
    }

    #[tracing::instrument(skip_all, err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn setup(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<VerifierPublicKeys>, Status> {
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
                            BridgeError::from(eyre::eyre!("failed to read operator params: {e}"))
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

        let verifier_public_keys = self.fetch_verifier_keys().await?;

        Ok(Response::new(VerifierPublicKeys::from(
            verifier_public_keys,
        )))
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
    // #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn new_deposit(
        &self,
        request: Request<Deposit>,
    ) -> Result<Response<clementine::RawSignedTx>, Status> {
        timed_request(OVERALL_DEPOSIT_TIMEOUT, "Overall new deposit", async {
            let deposit_info: DepositInfo = request.into_inner().try_into()?;

            let deposit_data = DepositData {
                deposit: deposit_info,
                nofn_xonly_pk: None,
                actors: Actors {
                    verifiers: self.fetch_verifier_keys().await?,
                    watchtowers: vec![],
                    operators: self.fetch_operator_keys().await?,
                },
                security_council: self.config.security_council.clone(),
            };

            let deposit_params = deposit_data.clone().into();

            // Collect and distribute keys needed keys from operators and watchtowers to verifiers
            let start = std::time::Instant::now();
            timed_request(
                KEY_DISTRIBUTION_TIMEOUT,
                "Key collection and distribution",
                self.collect_and_distribute_keys(&deposit_params),
            )
            .await?;
            tracing::info!("Collected and distributed keys in {:?}", start.elapsed());

            let verifiers = self.get_participating_verifiers(&deposit_data).await?;

            // Generate nonce streams for all verifiers.
            let num_required_sigs = self.config.get_num_required_nofn_sigs(&deposit_data);
            let num_required_nonces = num_required_sigs as u32 + 2; // ask for +2 for the final movetx signature + emergency stop signature, but don't send it on deposit_sign stage
            let (first_responses, nonce_streams) =
                    create_nonce_streams(
                        verifiers.clone(),
                        num_required_nonces,
                        #[cfg(test)]
                        &self.config,
                    )
                    .await?;

            // Create initial deposit session and send to verifiers
            let deposit_sign_session = DepositSignSession {
                deposit_params: Some(deposit_params.clone()),
                nonce_gen_first_responses: first_responses,
            };

            let deposit_sign_param: VerifierDepositSignParams =
                    deposit_sign_session.clone().into();

        #[allow(clippy::unused_enumerate_index)]
            let partial_sig_streams = timed_try_join_all(
                PARTIAL_SIG_STREAM_CREATION_TIMEOUT,
                "Partial signature stream creation",
                Some(verifiers.ids()),
                verifiers.clients().into_iter().enumerate().map(|(_idx, verifier_client)| {
                    let mut verifier_client = verifier_client.clone();
                    #[cfg(test)]
                    let config = self.config.clone();

                    let deposit_sign_param =
                    deposit_sign_param.clone();

                    async move {
                        #[cfg(test)]
                        config
                            .test_params
                            .timeout_params
                            .hook_timeout_partial_sig_stream_creation_verifier(_idx)
                            .await;

                        let (tx, rx) = tokio::sync::mpsc::channel(num_required_nonces as usize + 1); // initial param + num_required_nonces nonces

                        let stream = verifier_client
                            .deposit_sign(tokio_stream::wrappers::ReceiverStream::new(rx))
                            .await?
                            .into_inner();

                        tx.send(deposit_sign_param).await.map_err(|e| {
                            Status::internal(format!("Failed to send deposit sign session: {:?}", e))
                        })?;

                        Ok::<_, BridgeError>((stream, tx))
                    }
                })
            )
            .await?;

            // Set up deposit finalization streams
        #[allow(clippy::unused_enumerate_index)]
            let deposit_finalize_streams = verifiers.clients().into_iter().enumerate().map(
                    |(_idx, mut verifier)| {
                        let (tx, rx) = tokio::sync::mpsc::channel(num_required_nonces as usize + 1);
                        let receiver_stream = tokio_stream::wrappers::ReceiverStream::new(rx);
                        #[cfg(test)]
                        let config = self.config.clone();
                        // start deposit_finalize with tokio spawn
                        let deposit_finalize_future = tokio::spawn(async move {
                            #[cfg(test)]
                            config
                                .test_params
                                .timeout_params
                                .hook_timeout_deposit_finalize_verifier(_idx)
                                .await;

                            verifier.deposit_finalize(receiver_stream).await.map_err(BridgeError::from)
                        });

                        Ok::<_, BridgeError>((deposit_finalize_future, tx))
                    },
                ).collect::<Result<Vec<_>, BridgeError>>()?;

            tracing::info!("Sending deposit finalize streams to verifiers");

            let (deposit_finalize_futures, deposit_finalize_sender): (Vec<_>, Vec<_>) =
                deposit_finalize_streams.into_iter().unzip();

            // Send initial finalization params
            let deposit_finalize_first_param: VerifierDepositFinalizeParams =
                deposit_sign_session.clone().into();

            timed_try_join_all(
                DEPOSIT_FINALIZE_STREAM_CREATION_TIMEOUT,
                "Deposit finalization initial param send",
                Some(verifiers.ids()),
                deposit_finalize_sender.iter().cloned().map(|tx| {
                    let param = deposit_finalize_first_param.clone();
                    async move {
                        tx.send(param).await
                        .map_err(|e| {
                            Status::internal(format!(
                                "Failed to send deposit finalize first param: {:?}",
                                e
                            ))
                        }).map_err(Into::into)
                    }
                })
            ).await?;


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
            let (agg_nonce_sender, agg_nonce_receiver) = channel(num_required_nonces as usize);
            let (partial_sig_sender, partial_sig_receiver) = channel(num_required_nonces as usize);
            let (final_sig_sender, final_sig_receiver) = channel(num_required_nonces as usize);

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
            let operators = self.get_participating_operators(&deposit_data).await?;

            let config_clone = self.config.clone();
            let operator_sigs_fut = tokio::spawn(async move {
                timed_request(
                    OPERATOR_SIGS_TIMEOUT,
                    "Operator signature collection",
                    async {
                        Aggregator::collect_operator_sigs(
                            operators,
                            config_clone,
                            deposit_sign_session,
                        )
                        .await
                    },
                )
                .await
            });

            // Join the nonce aggregation handle to get the movetx agg nonce.
            let nonce_agg_handle = nonce_agg_handle
                .map_err(|_| Status::internal("panic when aggregating nonces"))
                .map(
                    |res| -> Result<(AggregatedNonce, AggregatedNonce), Status> {
                        res.and_then(|r| r.map_err(Into::into))
                    },
                )
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

            // Right now we collect all operator sigs then start to send them, we can do it simultaneously in the future
            // Need to change sig verification ordering in deposit_finalize() in verifiers so that we verify
            // 1st signature of all operators, then 2nd of all operators etc.
            let all_op_sigs = operator_sigs_fut
                .await
                .map_err(|_| Status::internal("panic when collecting operator signatures"))??;

            tracing::debug!("Got all operator signatures");

            tracing::debug!("Waiting for pipeline tasks to complete");
            // Wait for all pipeline tasks to complete
            timed_request(
                PIPELINE_COMPLETION_TIMEOUT,
                "MuSig2 signing pipeline",
                try_join_all([nonce_dist_handle, sig_agg_handle, sig_dist_handle]).map_err(|join_err| -> BridgeError { eyre::Report::from(join_err).wrap_err("Failed to join on pipelined tasks").into()}),
            )
            .await?;

            tracing::debug!("Pipeline tasks completed");


            // send operators sigs to verifiers after all verifiers have signed
            timed_request(
                SEND_OPERATOR_SIGS_TIMEOUT,
                "Sending operator signatures to verifiers",
                async {
                    let send_operator_sigs: Vec<_> = deposit_finalize_sender
                        .iter()
                        .map(|tx| async {
                            for one_op_sigs in all_op_sigs.iter() {
                                for sig in one_op_sigs.iter() {
                                    let deposit_finalize_param: VerifierDepositFinalizeParams =
                                        sig.into();

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
                    try_join_all(send_operator_sigs).await?;
                    Ok(())
                },
            )
            .await?;

            tracing::debug!("Waiting for deposit finalization");

            // Collect partial signatures for move transaction
            let partial_sigs: Vec<(Vec<u8>, Vec<u8>)> = timed_try_join_all(
                    DEPOSIT_FINALIZATION_TIMEOUT,
                    "Deposit finalization",
                    Some(verifiers.ids()),
                    deposit_finalize_futures.into_iter().map(|fut| async move {
                        let inner = fut.await
                            .map_err(|_| BridgeError::from(Status::internal("panic finishing deposit_finalize")))??
                            .into_inner();

                        Ok((inner.move_to_vault_partial_sig, inner.emergency_stop_partial_sig))
                    }),
                )
                .await?;


            let (move_to_vault_sigs, emergency_stop_sigs): (Vec<Vec<u8>>, Vec<Vec<u8>>) =
                partial_sigs.into_iter().unzip();

            tracing::debug!("Received move tx partial sigs: {:?}", move_to_vault_sigs);

            // Create the final move transaction and check the signatures
            let (movetx_agg_nonce, emergency_stop_agg_nonce) = nonce_agg_handle.await?;

            // Verify emergency stop signatures
            self.verify_and_save_emergency_stop_sigs(
                emergency_stop_sigs,
                emergency_stop_agg_nonce,
                deposit_params.clone(),
            )
            .await?;

            let signed_movetx_handler = self
                .create_movetx(move_to_vault_sigs, movetx_agg_nonce, deposit_params)
                .await?;

            let raw_signed_tx = RawSignedTx {
                raw_tx: bitcoin::consensus::serialize(&signed_movetx_handler.get_cached_tx()),
            };

            Ok(Response::new(raw_signed_tx))
        })
        .await.map_err(Into::into)
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn withdraw(
        &self,
        request: Request<AggregatorWithdrawalInput>,
    ) -> Result<Response<AggregatorWithdrawResponse>, Status> {
        let request = request.into_inner();
        let (withdraw_params, operator_xonly_pks) = (
            request.withdrawal.ok_or(Status::invalid_argument(
                "withdrawalParamsWithSig is missing",
            ))?,
            request.operator_xonly_pks,
        );
        // convert rpc xonly pks to bitcoin xonly pks
        let operator_xonly_pks_from_rpc: Vec<XOnlyPublicKey> = operator_xonly_pks
            .into_iter()
            .map(|xonly_pk| {
                xonly_pk.try_into().map_err(|e| {
                    Status::invalid_argument(format!("Failed to convert xonly public key: {}", e))
                })
            })
            .collect::<Result<Vec<_>, Status>>()?;

        // check if all given operator xonly pubkeys are a valid operator xonly pubkey, to warn the caller if
        // something is wrong with the given operator xonly pubkeys
        let current_operator_xonly_pks = self.fetch_operator_keys().await?;
        let invalid_operator_xonly_pks = operator_xonly_pks_from_rpc
            .iter()
            .filter(|xonly_pk| !current_operator_xonly_pks.contains(xonly_pk))
            .collect::<Vec<_>>();
        if !invalid_operator_xonly_pks.is_empty() {
            return Err(Status::invalid_argument(format!(
                "Given xonly public key doesn't belong to any current operator: invalid keys: {:?}, current operators: {:?}",
                invalid_operator_xonly_pks,
                current_operator_xonly_pks
            )));
        }

        let operators = self
            .get_operator_clients()
            .iter()
            .zip(current_operator_xonly_pks.into_iter());
        let withdraw_futures = operators
            .filter(|(_, xonly_pk)| {
                // check if operator_xonly_pks is empty or contains the operator's xonly public key
                operator_xonly_pks_from_rpc.is_empty()
                    || operator_xonly_pks_from_rpc.contains(xonly_pk)
            })
            .map(|(operator, operator_xonly_pk)| {
                let mut operator = operator.clone();
                let params = withdraw_params.clone();
                let mut request = Request::new(params);
                request.set_timeout(WITHDRAWAL_TIMEOUT);
                async move { (operator.withdraw(request).await, operator_xonly_pk) }
            });

        // collect responses from operators and return them as a vector of strings
        let responses = futures::future::join_all(withdraw_futures).await;
        Ok(Response::new(AggregatorWithdrawResponse {
            withdraw_responses: responses
                .into_iter()
                .map(|(res, xonly_pk)| match res {
                    Ok(withdraw_response) => {
                        let signed_tx = withdraw_response.into_inner().raw_tx;
                        let hex_tx = hex::encode(signed_tx);
                        format!(
                            "Withdraw successful for operator: {:?}, withdrawal tx: {}",
                            xonly_pk, hex_tx
                        )
                    }
                    Err(e) => format!("Withdraw failed for operator: {:?}, error: {}", xonly_pk, e),
                })
                .collect(),
        }))
    }

    async fn get_nofn_aggregated_xonly_pk(
        &self,
        _: tonic::Request<super::Empty>,
    ) -> std::result::Result<tonic::Response<super::NofnResponse>, tonic::Status> {
        let verifier_keys = self.fetch_verifier_keys().await?;
        let num_verifiers = verifier_keys.len();
        let nofn_xonly_pk = bitcoin::XOnlyPublicKey::from_musig2_pks(verifier_keys, None)
            .expect("Failed to aggregate verifier public keys");
        Ok(Response::new(super::NofnResponse {
            nofn_xonly_pk: nofn_xonly_pk.serialize().to_vec(),
            num_verifiers: num_verifiers as u32,
        }))
    }

    async fn internal_get_emergency_stop_tx(
        &self,
        request: Request<clementine::GetEmergencyStopTxRequest>,
    ) -> Result<Response<clementine::GetEmergencyStopTxResponse>, Status> {
        let inner_request = request.into_inner();
        let txids: Vec<Txid> = inner_request
            .txids
            .into_iter()
            .map(|txid| {
                Txid::from_slice(&txid.txid).map_err(|e| {
                    tonic::Status::invalid_argument(format!("Failed to parse txid: {e}"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let emergency_stop_txs = self.db.get_emergency_stop_txs(None, txids).await?;

        let (txids, encrypted_emergency_stop_txs): (Vec<Txid>, Vec<Vec<u8>>) =
            emergency_stop_txs.into_iter().unzip();

        Ok(Response::new(clementine::GetEmergencyStopTxResponse {
            txids: txids.into_iter().map(|txid| txid.into()).collect(),
            encrypted_emergency_stop_txs,
        }))
    }

    async fn send_move_to_vault_tx(
        &self,
        request: Request<clementine::SendMoveTxRequest>,
    ) -> Result<Response<clementine::Txid>, Status> {
        #[cfg(not(feature = "automation"))]
        {
            let _ = request;
            return Err(Status::unimplemented(
                "Automation is disabled, cannot automatically send move to vault tx.",
            ));
        }

        #[cfg(feature = "automation")]
        {
            let request = request.into_inner();
            let movetx = bitcoin::consensus::deserialize(
                &request
                    .raw_tx
                    .ok_or_eyre("raw_tx is required")
                    .map_to_status()?
                    .raw_tx,
            )
            .wrap_err("Failed to deserialize movetx")
            .map_to_status()?;

            let mut dbtx = self.db.begin_transaction().await?;
            self.tx_sender
                .insert_try_to_send(
                    &mut dbtx,
                    Some(TxMetadata {
                        deposit_outpoint: request
                            .deposit_outpoint
                            .map(TryInto::try_into)
                            .transpose()?,
                        operator_xonly_pk: None,
                        round_idx: None,
                        kickoff_idx: None,
                        tx_type: TransactionType::MoveToVault,
                    }),
                    &movetx,
                    FeePayingType::CPFP,
                    None,
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

            Ok(Response::new(movetx.compute_txid().into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::actor::Actor;
    use crate::config::BridgeConfig;
    use crate::deposit::{BaseDepositData, DepositInfo, DepositType};
    use crate::musig2::AggregateFromPublicKeys;
    use crate::rpc::clementine::clementine_aggregator_client::ClementineAggregatorClient;
    use crate::rpc::clementine::{self, GetEntityStatusesRequest, SendMoveTxRequest};
    use crate::rpc::get_clients;
    use crate::servers::create_aggregator_unix_server;
    use crate::test::common::citrea::MockCitreaClient;
    use crate::test::common::tx_utils::ensure_tx_onchain;
    use crate::test::common::*;
    use crate::{builder, EVMAddress};
    use bitcoin::hashes::Hash;
    use bitcoincore_rpc::RpcApi;
    use eyre::Context;
    use std::time::Duration;
    use tokio::time::sleep;
    use tonic::{Request, Status};

    #[cfg(feature = "automation")]
    async fn perform_deposit(mut config: BridgeConfig) -> Result<(), Status> {
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc();

        let _unused =
            run_single_deposit::<MockCitreaClient>(&mut config, rpc.clone(), None, None, None)
                .await?;

        Ok(())
    }
    #[tokio::test]
    #[ignore = "See #687"]
    async fn aggregator_double_setup_fail() {
        let mut config = create_test_config_with_thread_name().await;
        let _regtest = create_regtest_rpc(&mut config).await;

        let actors = create_actors::<MockCitreaClient>(&config).await;
        let mut aggregator = actors.get_aggregator();

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
    async fn aggregator_double_deposit() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc();
        let actors = create_actors::<MockCitreaClient>(&config).await;
        let mut aggregator = actors.get_aggregator();

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

        // Two deposits with the same values.
        let movetx_one = aggregator
            .new_deposit(clementine::Deposit::from(deposit_info.clone()))
            .await
            .unwrap()
            .into_inner();
        let movetx_one_txid: bitcoin::Txid = aggregator
            .send_move_to_vault_tx(SendMoveTxRequest {
                deposit_outpoint: Some(deposit_outpoint.into()),
                raw_tx: Some(movetx_one),
            })
            .await
            .unwrap()
            .into_inner()
            .try_into()
            .unwrap();

        let movetx_two = aggregator
            .new_deposit(clementine::Deposit::from(deposit_info))
            .await
            .unwrap()
            .into_inner();
        let _movetx_two_txid: bitcoin::Txid = aggregator
            .send_move_to_vault_tx(SendMoveTxRequest {
                deposit_outpoint: Some(deposit_outpoint.into()),
                raw_tx: Some(movetx_two),
            })
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
                    .get_raw_transaction_info(&movetx_one_txid, None)
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

    #[tokio::test(flavor = "multi_thread")]
    async fn aggregator_deposit_movetx_lands_onchain() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc();
        let actors = create_actors::<MockCitreaClient>(&config).await;
        let mut aggregator = actors.get_aggregator();

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

        // Generate and broadcast the move-to-vault transaction
        let raw_move_tx = aggregator
            .new_deposit(clementine::Deposit::from(deposit_info))
            .await
            .unwrap()
            .into_inner();

        let movetx_txid = aggregator
            .send_move_to_vault_tx(SendMoveTxRequest {
                deposit_outpoint: Some(deposit_outpoint.into()),
                raw_tx: Some(raw_move_tx),
            })
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

    #[tokio::test]
    async fn aggregator_two_deposit_movetx_and_emergency_stop() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc();
        let actors = create_actors::<MockCitreaClient>(&config).await;
        let mut aggregator = actors.get_aggregator();

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

        let deposit_address_0 = builder::address::generate_deposit_address(
            nofn_xonly_pk,
            signer.address.as_unchecked(),
            evm_address,
            config.protocol_paramset().network,
            config.protocol_paramset().user_takes_after,
        )
        .unwrap()
        .0;

        let deposit_address_1 = builder::address::generate_deposit_address(
            nofn_xonly_pk,
            signer.address.as_unchecked(),
            evm_address,
            config.protocol_paramset().network,
            config.protocol_paramset().user_takes_after,
        )
        .unwrap()
        .0;

        let deposit_outpoint_0 = rpc
            .send_to_address(&deposit_address_0, config.protocol_paramset().bridge_amount)
            .await
            .unwrap();
        rpc.mine_blocks(18).await.unwrap();

        let deposit_outpoint_1 = rpc
            .send_to_address(&deposit_address_1, config.protocol_paramset().bridge_amount)
            .await
            .unwrap();
        rpc.mine_blocks(18).await.unwrap();

        let deposit_info_0 = DepositInfo {
            deposit_outpoint: deposit_outpoint_0,
            deposit_type: DepositType::BaseDeposit(BaseDepositData {
                evm_address,
                recovery_taproot_address: signer.address.as_unchecked().clone(),
            }),
        };

        let deposit_info_1 = DepositInfo {
            deposit_outpoint: deposit_outpoint_1,
            deposit_type: DepositType::BaseDeposit(BaseDepositData {
                evm_address,
                recovery_taproot_address: signer.address.as_unchecked().clone(),
            }),
        };

        // Generate and broadcast the move-to-vault tx for the first deposit
        let raw_move_tx_0 = aggregator
            .new_deposit(clementine::Deposit::from(deposit_info_0))
            .await
            .unwrap()
            .into_inner();
        let move_txid_0: bitcoin::Txid = aggregator
            .send_move_to_vault_tx(SendMoveTxRequest {
                deposit_outpoint: Some(deposit_outpoint_0.into()),
                raw_tx: Some(raw_move_tx_0),
            })
            .await
            .unwrap()
            .into_inner()
            .try_into()
            .unwrap();

        rpc.mine_blocks(1).await.unwrap();
        sleep(Duration::from_secs(3)).await;
        ensure_tx_onchain(rpc, move_txid_0)
            .await
            .expect("failed to get movetx_0 on chain");

        // Generate and broadcast the move-to-vault tx for the second deposit
        let raw_move_tx_1 = aggregator
            .new_deposit(clementine::Deposit::from(deposit_info_1))
            .await
            .unwrap()
            .into_inner();
        let move_txid_1 = aggregator
            .send_move_to_vault_tx(SendMoveTxRequest {
                deposit_outpoint: Some(deposit_outpoint_1.into()),
                raw_tx: Some(raw_move_tx_1),
            })
            .await
            .unwrap()
            .into_inner()
            .try_into()
            .unwrap();

        rpc.mine_blocks(1).await.unwrap();
        ensure_tx_onchain(rpc, move_txid_1)
            .await
            .expect("failed to get movetx_1 on chain");
        sleep(Duration::from_secs(3)).await;

        let move_txids = vec![move_txid_0, move_txid_1];

        tracing::debug!("Move txids: {:?}", move_txids);

        let emergency_txid = aggregator
            .internal_get_emergency_stop_tx(tonic::Request::new(
                clementine::GetEmergencyStopTxRequest {
                    txids: move_txids
                        .iter()
                        .map(|txid| clementine::Txid {
                            txid: txid.to_byte_array().to_vec(),
                        })
                        .collect(),
                },
            ))
            .await
            .unwrap()
            .into_inner();

        let decryption_priv_key =
            hex::decode("a80bc8cf095c2b37d4c6233114e0dd91f43d75de5602466232dbfcc1fc66c542")
                .expect("Failed to parse emergency stop encryption public key");
        let emergency_stop_tx: bitcoin::Transaction = bitcoin::consensus::deserialize(
            &crate::encryption::decrypt_bytes(
                &decryption_priv_key,
                &emergency_txid.encrypted_emergency_stop_txs[0],
            )
            .expect("Failed to decrypt emergency stop tx"),
        )
        .expect("Failed to deserialize");

        rpc.client
            .send_raw_transaction(&emergency_stop_tx)
            .await
            .expect("Failed to send emergency stop tx");

        let emergency_stop_txid = emergency_stop_tx.compute_txid();
        rpc.mine_blocks(1).await.unwrap();

        let _emergencty_tx = poll_get(
            async || {
                rpc.mine_blocks(1).await.unwrap();

                let tx_result = rpc
                    .client
                    .get_raw_transaction_info(&emergency_stop_txid, None)
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
        .wrap_err_with(|| eyre::eyre!("Emergency stop tx did not land onchain"))
        .unwrap();
    }

    #[cfg(feature = "automation")]
    #[tokio::test]
    #[ignore = "This test does not work"]
    async fn aggregator_deposit_finalize_verifier_timeout() {
        let mut config = create_test_config_with_thread_name().await;
        config
            .test_params
            .timeout_params
            .deposit_finalize_verifier_idx = Some(0);
        let res = perform_deposit(config).await;
        assert!(res.is_err());
        let err_string = res.unwrap_err().to_string();
        assert!(
            err_string.contains("Deposit finalization from verifiers"),
            "Error string was: {}",
            err_string
        );
    }

    #[cfg(feature = "automation")]
    #[tokio::test]
    async fn aggregator_deposit_key_distribution_verifier_timeout() {
        let mut config = create_test_config_with_thread_name().await;
        config
            .test_params
            .timeout_params
            .key_distribution_verifier_idx = Some(0);

        let res = perform_deposit(config).await;

        assert!(res.is_err());
        let err_string = res.unwrap_err().to_string();
        assert!(
            err_string.contains("Verifier key distribution (id:"),
            "Error string was: {}",
            err_string
        );
    }

    #[cfg(feature = "automation")]
    #[tokio::test]
    async fn aggregator_deposit_key_distribution_operator_timeout() {
        let mut config = create_test_config_with_thread_name().await;
        config
            .test_params
            .timeout_params
            .key_collection_operator_idx = Some(0);

        let res = perform_deposit(config).await;

        assert!(res.is_err());
        let err_string = res.unwrap_err().to_string();
        assert!(
            err_string.contains("Operator key collection (id:"),
            "Error string was: {}",
            err_string
        );
    }

    #[cfg(feature = "automation")]
    #[tokio::test]
    async fn aggregator_deposit_nonce_stream_creation_verifier_timeout() {
        let mut config = create_test_config_with_thread_name().await;
        config
            .test_params
            .timeout_params
            .nonce_stream_creation_verifier_idx = Some(0);

        let res = perform_deposit(config).await;

        assert!(res.is_err());
        let err_string = res.unwrap_err().to_string();
        assert!(
            err_string.contains("Nonce stream creation (id:"),
            "Error string was: {}",
            err_string
        );
    }

    #[cfg(feature = "automation")]
    #[tokio::test]
    async fn aggregator_deposit_partial_sig_stream_creation_timeout() {
        let mut config = create_test_config_with_thread_name().await;
        config
            .test_params
            .timeout_params
            .partial_sig_stream_creation_verifier_idx = Some(0);

        let res = perform_deposit(config).await;

        assert!(res.is_err());
        let err_string = res.unwrap_err().to_string();
        assert!(
            err_string.contains("Partial signature stream creation (id:"),
            "Error string was: {}",
            err_string
        );
    }

    #[cfg(feature = "automation")]
    #[tokio::test]
    async fn aggregator_deposit_operator_sig_collection_operator_timeout() {
        let mut config = create_test_config_with_thread_name().await;
        config
            .test_params
            .timeout_params
            .operator_sig_collection_operator_idx = Some(0);

        let res = perform_deposit(config).await;

        assert!(res.is_err());
        let err_string = res.unwrap_err().to_string();
        assert!(
            err_string.contains("Operator signature stream creation (id:"),
            "Error string was: {}",
            err_string
        );
    }

    #[tokio::test]
    async fn aggregator_get_entity_statuses() {
        let mut config = create_test_config_with_thread_name().await;
        let _regtest = create_regtest_rpc(&mut config).await;

        let actors = create_actors::<MockCitreaClient>(&config).await;
        let mut aggregator = actors.get_aggregator();
        let status = aggregator
            .get_entity_statuses(Request::new(GetEntityStatusesRequest {
                restart_tasks: false,
            }))
            .await
            .unwrap()
            .into_inner();

        tracing::info!("Status: {:?}", status);

        assert_eq!(
            status.entity_statuses.len(),
            config.test_params.all_operators_secret_keys.len()
                + config.test_params.all_verifiers_secret_keys.len()
        );
    }

    #[tokio::test]
    async fn aggregator_start_with_offline_verifier() {
        let mut config = create_test_config_with_thread_name().await;
        // random ips
        config.verifier_endpoints = Some(vec!["https://142.143.144.145:17001".to_string()]);
        config.operator_endpoints = Some(vec!["https://142.143.144.145:17002".to_string()]);
        // Create temporary directory for aggregator socket
        let socket_dir = tempfile::tempdir().unwrap();
        let socket_path = socket_dir.path().join("aggregator.sock");

        tracing::info!("Creating unix aggregator server");

        let (_, _shutdown_tx) = create_aggregator_unix_server(config.clone(), socket_path.clone())
            .await
            .unwrap();

        tracing::info!("Created unix aggregator server");

        let mut aggregator_client = get_clients(
            vec![format!("unix://{}", socket_path.display())],
            ClementineAggregatorClient::new,
            &config,
            false,
        )
        .await
        .unwrap()
        .pop()
        .unwrap();

        tracing::info!("Got aggregator client");

        // vergen should work
        assert!(aggregator_client
            .vergen(Request::new(clementine::Empty {}))
            .await
            .is_ok());

        tracing::info!("After vergen");

        // setup should give error as it can't connect to the verifier
        assert!(aggregator_client
            .setup(Request::new(clementine::Empty {}))
            .await
            .is_err());

        tracing::info!("After setup");

        // aggregator should still be up even after not connecting to the verifier
        // and should be able to get metrics
        tracing::info!(
            "Entity statuses: {:?}",
            aggregator_client
                .get_entity_statuses(Request::new(GetEntityStatusesRequest {
                    restart_tasks: false,
                }))
                .await
                .unwrap()
        );
    }
}
