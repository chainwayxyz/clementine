use super::clementine::{
    self, clementine_verifier_server::ClementineVerifier, Empty, NonceGenRequest, NonceGenResponse,
    OperatorParams, OptimisticPayoutParams, PartialSig, RawTxWithRbfInfo, SignedTxWithType,
    SignedTxsWithType, VergenResponse, VerifierDepositFinalizeParams, VerifierDepositSignParams,
    VerifierParams,
};
use super::error;
use super::parser::ParserError;
use crate::builder::transaction::sign::{create_and_sign_txs, TransactionRequestData};
use crate::citrea::CitreaClientT;
use crate::rpc::clementine::VerifierDepositFinalizeResponse;
use crate::utils::get_vergen_response;
use crate::verifier::VerifierServer;
use crate::{constants, fetch_next_optional_message_from_stream};
use crate::{
    fetch_next_message_from_stream,
    rpc::parser::{self},
};
use bitcoin::Witness;
use clementine::verifier_deposit_finalize_params::Params;
use secp256k1::musig::AggregatedNonce;
use tokio::sync::mpsc::{self, error::SendError};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{async_trait, Request, Response, Status, Streaming};

#[async_trait]
impl<C> ClementineVerifier for VerifierServer<C>
where
    C: CitreaClientT,
{
    async fn vergen(&self, _request: Request<Empty>) -> Result<Response<VergenResponse>, Status> {
        Ok(Response::new(get_vergen_response()))
    }

    async fn restart_background_tasks(
        &self,
        _request: tonic::Request<super::Empty>,
    ) -> std::result::Result<tonic::Response<super::Empty>, tonic::Status> {
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            self.start_background_tasks(),
        )
        .await;
        match result {
            Ok(Ok(_)) => Ok(tonic::Response::new(super::Empty {})),
            Ok(Err(e)) => Err(e.into()),
            Err(_) => Err(tonic::Status::deadline_exceeded(
                "Timed out while restarting background tasks. Recommended to restart the verifier manually.",
            )),
        }
    }

    async fn optimistic_payout_sign(
        &self,
        request: Request<OptimisticPayoutParams>,
    ) -> Result<Response<PartialSig>, Status> {
        let params = request.into_inner();
        let agg_nonce = AggregatedNonce::from_byte_array(
            params
                .agg_nonce
                .as_slice()
                .try_into()
                .map_err(|_| Status::invalid_argument("agg_nonce must be exactly 66 bytes"))?,
        )
        .map_err(|e| Status::invalid_argument(format!("Invalid musigagg nonce: {}", e)))?;
        let nonce_session_id = params
            .nonce_gen
            .ok_or(Status::invalid_argument(
                "Nonce params not found for optimistic payout",
            ))?
            .id;
        let withdraw_params = params.withdrawal.ok_or(Status::invalid_argument(
            "Withdrawal params not found for optimistic payout",
        ))?;
        let (withdrawal_id, input_signature, input_outpoint, output_script_pubkey, output_amount) =
            parser::operator::parse_withdrawal_sig_params(withdraw_params).await?;
        let partial_sig = self
            .verifier
            .sign_optimistic_payout(
                nonce_session_id,
                agg_nonce,
                withdrawal_id,
                input_signature,
                input_outpoint,
                output_script_pubkey,
                output_amount,
            )
            .await?;
        Ok(Response::new(partial_sig.into()))
    }

    async fn internal_create_watchtower_challenge(
        &self,
        request: tonic::Request<super::TransactionRequest>,
    ) -> std::result::Result<tonic::Response<super::RawTxWithRbfInfo>, tonic::Status> {
        let transaction_request = request.into_inner();
        let transaction_data: TransactionRequestData = transaction_request.try_into()?;

        let (_tx_type, signed_tx, rbf_info) = self
            .verifier
            .create_watchtower_challenge(
                transaction_data,
                &{
                    let challenge_bytes = self
                        .verifier
                        .config
                        .protocol_paramset()
                        .watchtower_challenge_bytes;
                    let mut challenge = vec![0u8; challenge_bytes];
                    for (step, i) in (0..challenge_bytes).step_by(32).enumerate() {
                        if i < challenge_bytes {
                            challenge[i] = step as u8;
                        }
                    }
                    challenge
                }, // dummy challenge with 1u8, 2u8 every 32 bytes
            )
            .await?;

        Ok(Response::new(RawTxWithRbfInfo {
            raw_tx: bitcoin::consensus::serialize(&signed_tx),
            rbf_info: Some(rbf_info.into()),
        }))
    }
    type NonceGenStream = ReceiverStream<Result<NonceGenResponse, Status>>;
    type DepositSignStream = ReceiverStream<Result<PartialSig, Status>>;

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn get_params(&self, _: Request<Empty>) -> Result<Response<VerifierParams>, Status> {
        let params: VerifierParams = (&self.verifier).try_into()?;

        Ok(Response::new(params))
    }

    #[tracing::instrument(skip_all, err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn set_operator(
        &self,
        req: Request<Streaming<OperatorParams>>,
    ) -> Result<Response<Empty>, Status> {
        let mut in_stream = req.into_inner();

        let (collateral_funding_outpoint, operator_xonly_pk, wallet_reimburse_address) =
            parser::operator::parse_details(&mut in_stream).await?;

        // check if address is valid
        let wallet_reimburse_address_checked = wallet_reimburse_address
            .clone()
            .require_network(self.verifier.config.protocol_paramset().network)
            .map_err(|e| {
                Status::invalid_argument(format!(
                    "Invalid operator reimbursement address: {:?} for bitcoin network {:?} for operator {:?}. ParseError: {}",
                    wallet_reimburse_address,
                    self.verifier.config.protocol_paramset().network,
                    operator_xonly_pk,
                    e
                ))
            })?;

        let mut operator_kickoff_winternitz_public_keys = Vec::new();
        // we need num_round_txs + 1 because the last round includes reimburse generators of previous round
        for _ in 0..self.verifier.config.get_num_kickoff_winternitz_pks() {
            operator_kickoff_winternitz_public_keys
                .push(parser::operator::parse_winternitz_public_keys(&mut in_stream).await?);
        }

        let mut unspent_kickoff_sigs =
            Vec::with_capacity(self.verifier.config.get_num_unspent_kickoff_sigs());
        for _ in 0..self.verifier.config.get_num_unspent_kickoff_sigs() {
            unspent_kickoff_sigs.push(parser::operator::parse_schnorr_sig(&mut in_stream).await?);
        }

        if in_stream.message().await?.is_some() {
            return Err(Status::invalid_argument(
                "Expected end of stream, got more messages in set_operator",
            ));
        }

        self.verifier
            .set_operator(
                collateral_funding_outpoint,
                operator_xonly_pk,
                wallet_reimburse_address_checked,
                operator_kickoff_winternitz_public_keys,
                unspent_kickoff_sigs,
            )
            .await?;

        Ok(Response::new(Empty {}))
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn nonce_gen(
        &self,
        req: Request<NonceGenRequest>,
    ) -> Result<Response<Self::NonceGenStream>, Status> {
        let num_nonces = req.into_inner().num_nonces;

        let (session_id, pub_nonces) = self.verifier.nonce_gen(num_nonces).await?;

        let (tx, rx) = mpsc::channel(pub_nonces.len() + 1);

        tokio::spawn(async move {
            let nonce_gen_first_response = clementine::NonceGenFirstResponse {
                id: session_id,
                num_nonces,
            };
            let session_id: NonceGenResponse = nonce_gen_first_response.into();
            tx.send(Ok(session_id)).await?;

            for pub_nonce in &pub_nonces {
                let pub_nonce: NonceGenResponse = pub_nonce.into();
                tx.send(Ok(pub_nonce)).await?;
            }

            Ok::<(), SendError<_>>(())
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn deposit_sign(
        &self,
        req: Request<Streaming<VerifierDepositSignParams>>,
    ) -> Result<Response<Self::DepositSignStream>, Status> {
        let mut in_stream = req.into_inner();
        let verifier = self.verifier.clone();

        let (tx, rx) = mpsc::channel(constants::DEFAULT_CHANNEL_SIZE);
        let out_stream: Self::DepositSignStream = ReceiverStream::new(rx);

        let (param_tx, mut param_rx) = mpsc::channel(1);
        let (agg_nonce_tx, agg_nonce_rx) = mpsc::channel(constants::DEFAULT_CHANNEL_SIZE);

        // Send incoming data to deposit sign job.
        tokio::spawn(async move {
            let params = fetch_next_message_from_stream!(in_stream, params)?;
            let (deposit_data, session_id) = match params {
                clementine::verifier_deposit_sign_params::Params::DepositSignFirstParam(
                    deposit_sign_session,
                ) => parser::verifier::parse_deposit_sign_session(
                    deposit_sign_session,
                    &verifier.signer.public_key,
                )?,
                _ => return Err(Status::invalid_argument("Expected DepositOutpoint")),
            };
            param_tx
                .send((deposit_data, session_id))
                .await
                .map_err(error::output_stream_ended_prematurely)?;

            while let Some(result) =
                fetch_next_optional_message_from_stream!(&mut in_stream, params)
            {
                let agg_nonce = match result {
                    clementine::verifier_deposit_sign_params::Params::AggNonce(agg_nonce) => {
                        AggregatedNonce::from_byte_array(
                            agg_nonce.as_slice().try_into().map_err(|_| {
                                ParserError::RPCParamMalformed("AggNonce".to_string())
                            })?,
                        )
                        .map_err(|_| ParserError::RPCParamMalformed("AggNonce".to_string()))?
                    }
                    _ => return Err(Status::invalid_argument("Expected AggNonce")),
                };

                agg_nonce_tx
                    .send(agg_nonce)
                    .await
                    .map_err(error::output_stream_ended_prematurely)?;
            }
            Ok(())
        });

        // Start partial sig job and return partial sig responses.
        tokio::spawn(async move {
            let (deposit_data, session_id) = param_rx
                .recv()
                .await
                .ok_or(error::expected_msg_got_none("parameters")())?;

            let mut partial_sig_receiver = verifier
                .deposit_sign(deposit_data.clone(), session_id, agg_nonce_rx)
                .await?;

            let mut nonce_idx = 0;
            let num_required_sigs = verifier.config.get_num_required_nofn_sigs(&deposit_data);
            while let Some(partial_sig) = partial_sig_receiver.recv().await {
                tx.send(Ok(PartialSig {
                    partial_sig: partial_sig.serialize().to_vec(),
                }))
                .await
                .map_err(|e| {
                    Status::aborted(format!(
                        "Error sending partial sig, stream ended prematurely: {e}"
                    ))
                })?;

                nonce_idx += 1;
                tracing::trace!(
                    "Verifier {:?} signed and sent sighash {} of {} through rpc deposit_sign",
                    verifier.signer.public_key,
                    nonce_idx,
                    num_required_sigs
                );
                if nonce_idx == num_required_sigs {
                    break;
                }
            }

            Ok::<(), Status>(())
        });

        Ok(Response::new(out_stream))
    }

    /// Function to finalize the deposit. Verifier will check the validity of the both nofn signatures and
    /// operator signatures. It will receive data from the stream in this order -> nofn sigs, movetx agg nonce, operator sigs.
    /// If everything is correct, it will partially sign the move tx and send it to aggregator.
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn deposit_finalize(
        &self,
        req: Request<Streaming<VerifierDepositFinalizeParams>>,
    ) -> Result<Response<VerifierDepositFinalizeResponse>, Status> {
        let mut in_stream = req.into_inner();
        tracing::trace!(
            "In verifier {:?} deposit_finalize()",
            self.verifier.signer.public_key
        );

        let (sig_tx, sig_rx) = mpsc::channel(constants::DEFAULT_CHANNEL_SIZE);
        let (agg_nonce_tx, agg_nonce_rx) = mpsc::channel(1);
        let (operator_sig_tx, operator_sig_rx) = mpsc::channel(constants::DEFAULT_CHANNEL_SIZE);

        let params = fetch_next_message_from_stream!(in_stream, params)?;
        let (deposit_data, session_id) = match params {
            Params::DepositSignFirstParam(deposit_sign_session) => {
                parser::verifier::parse_deposit_sign_session(
                    deposit_sign_session,
                    &self.verifier.signer.public_key,
                )?
            }
            _ => Err(Status::internal("Expected DepositOutpoint"))?,
        };
        tracing::trace!(
            "Verifier {:?} got DepositSignFirstParam in deposit_finalize()",
            self.verifier.signer.public_key
        );

        // Start deposit finalize job.
        let verifier = self.verifier.clone();
        let mut dep_data = deposit_data.clone();
        let deposit_finalize_handle = tokio::spawn(async move {
            verifier
                .deposit_finalize(
                    &mut dep_data,
                    session_id,
                    sig_rx,
                    agg_nonce_rx,
                    operator_sig_rx,
                )
                .await
        });

        // Start parsing inputs and send them to deposit finalize job.
        let verifier = self.verifier.clone();
        tokio::spawn(async move {
            let num_required_nofn_sigs = verifier.config.get_num_required_nofn_sigs(&deposit_data);
            let mut nonce_idx = 0;
            while let Some(sig) =
                parser::verifier::parse_next_deposit_finalize_param_schnorr_sig(&mut in_stream)
                    .await?
            {
                tracing::debug!(
                    "Received full nofn sig {} in deposit_finalize()",
                    nonce_idx + 1
                );
                sig_tx
                    .send(sig)
                    .await
                    .map_err(error::output_stream_ended_prematurely)?;
                tracing::debug!(
                    "Sent full nofn sig {} to src/verifier in deposit_finalize()",
                    nonce_idx + 1
                );
                nonce_idx += 1;
                if nonce_idx == num_required_nofn_sigs {
                    break;
                }
            }
            if nonce_idx < num_required_nofn_sigs {
                panic!(
                    "Expected more nofn sigs {} < {}",
                    nonce_idx, num_required_nofn_sigs
                )
            }

            let move_tx_agg_nonce =
                parser::verifier::parse_deposit_finalize_param_move_tx_agg_nonce(&mut in_stream)
                    .await?;
            agg_nonce_tx
                .send(move_tx_agg_nonce)
                .await
                .map_err(error::output_stream_ended_prematurely)?;

            let emergency_stop_agg_nonce =
                parser::verifier::parse_deposit_finalize_param_emergency_stop_agg_nonce(
                    &mut in_stream,
                )
                .await?;
            agg_nonce_tx
                .send(emergency_stop_agg_nonce)
                .await
                .map_err(error::output_stream_ended_prematurely)?;

            let num_required_op_sigs = verifier
                .config
                .get_num_required_operator_sigs(&deposit_data);
            let num_operators = deposit_data.get_num_operators();
            let num_required_total_op_sigs = num_required_op_sigs * num_operators;
            let mut total_op_sig_count = 0;
            for _ in 0..num_operators {
                let mut op_sig_count = 0;

                while let Some(operator_sig) =
                    parser::verifier::parse_next_deposit_finalize_param_schnorr_sig(&mut in_stream)
                        .await?
                {
                    tracing::debug!(
                        "Received full operator sig {} in deposit_finalize()",
                        op_sig_count + 1
                    );
                    operator_sig_tx
                        .send(operator_sig)
                        .await
                        .map_err(error::output_stream_ended_prematurely)?;
                    tracing::debug!(
                        "Sent full operator sig {} to src/verifier in deposit_finalize()",
                        op_sig_count + 1
                    );

                    op_sig_count += 1;
                    total_op_sig_count += 1;
                    if op_sig_count == num_required_op_sigs {
                        break;
                    }
                }
            }

            if total_op_sig_count < num_required_total_op_sigs {
                panic!(
                    "Not enough operator signatures. Needed: {}, received: {}",
                    num_required_total_op_sigs, total_op_sig_count
                );
            }

            Ok::<(), Status>(())
        });

        let partial_sig = deposit_finalize_handle.await.map_err(|e| {
            Status::internal(format!("Deposit finalize thread failed to finish: {}", e).as_str())
        })??;

        let response = VerifierDepositFinalizeResponse {
            move_to_vault_partial_sig: partial_sig.0.serialize().to_vec(),
            emergency_stop_partial_sig: partial_sig.1.serialize().to_vec(),
        };

        Ok(Response::new(response))
    }

    async fn set_operator_keys(
        &self,
        request: tonic::Request<super::OperatorKeysWithDeposit>,
    ) -> std::result::Result<tonic::Response<super::Empty>, tonic::Status> {
        let data = request.into_inner();
        let (deposit_params, op_keys, operator_xonly_pk) =
            parser::verifier::parse_op_keys_with_deposit(data)?;
        self.verifier
            .set_operator_keys(deposit_params, op_keys, operator_xonly_pk)
            .await?;
        Ok(Response::new(Empty {}))
    }

    async fn internal_create_signed_txs(
        &self,
        request: tonic::Request<super::TransactionRequest>,
    ) -> std::result::Result<tonic::Response<super::SignedTxsWithType>, tonic::Status> {
        let transaction_request = request.into_inner();
        let transaction_data: TransactionRequestData = transaction_request.try_into()?;
        let raw_txs = create_and_sign_txs(
            self.verifier.db.clone(),
            &self.verifier.signer,
            self.verifier.config.clone(),
            transaction_data,
            None, // empty blockhash, will not sign this
        )
        .await?;

        Ok(Response::new(SignedTxsWithType {
            signed_txs: raw_txs
                .into_iter()
                .map(|(tx_type, signed_tx)| SignedTxWithType {
                    transaction_type: Some(tx_type.into()),
                    raw_tx: bitcoin::consensus::serialize(&signed_tx),
                })
                .collect(),
        }))
    }

    async fn internal_handle_kickoff(
        &self,
        request: Request<clementine::Txid>,
    ) -> Result<Response<Empty>, Status> {
        let txid = request.into_inner();
        let txid = bitcoin::Txid::try_from(txid).expect("Should be able to convert");
        let mut dbtx = self.verifier.db.begin_transaction().await?;
        let kickoff_data = self
            .verifier
            .db
            .get_deposit_data_with_kickoff_txid(None, txid)
            .await?;
        if let Some((deposit_data, kickoff_id)) = kickoff_data {
            self.verifier
                .handle_kickoff(&mut dbtx, Witness::new(), deposit_data, kickoff_id, false)
                .await?;
        } else {
            return Err(Status::not_found("Kickoff txid not found"));
        }
        dbtx.commit().await.expect("Failed to commit transaction");
        Ok(Response::new(Empty {}))
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn debug_tx(
        &self,
        request: tonic::Request<super::TxDebugRequest>,
    ) -> std::result::Result<tonic::Response<super::TxDebugInfo>, tonic::Status> {
        #[cfg(not(feature = "automation"))]
        {
            Err(tonic::Status::unimplemented(
                "Automation is not enabled, TxSender is not running.",
            ))
        }

        // Get debug info from tx_sender
        #[cfg(feature = "automation")]
        {
            let tx_id = request.into_inner().tx_id;

            match self.verifier.tx_sender.debug_tx(tx_id).await {
                Ok(debug_info) => Ok(tonic::Response::new(debug_info)),
                Err(e) => Err(tonic::Status::internal(format!(
                    "Failed to debug TX {}: {}",
                    tx_id, e
                ))),
            }
        }
    }
}
