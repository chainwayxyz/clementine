use super::clementine::{
    self, clementine_verifier_server::ClementineVerifier, Empty, NonceGenRequest, NonceGenResponse,
    OperatorParams, PartialSig, RawSignedTx, TransactionRequest, VerifierDepositFinalizeParams,
    VerifierDepositSignParams, VerifierParams, VerifierPublicKeys, WatchtowerParams,
};
use super::error;
use crate::builder::sighash::{
    calculate_num_required_nofn_sigs, calculate_num_required_operator_sigs,
};
use crate::builder::transaction::sign::create_and_sign_tx;
use crate::fetch_next_optional_message_from_stream;
use crate::rpc::parser::parse_transaction_request;
use crate::{
    errors::BridgeError,
    fetch_next_message_from_stream,
    rpc::parser::{self},
    verifier::Verifier,
};
use bitcoin::secp256k1::PublicKey;
use clementine::verifier_deposit_finalize_params::Params;
use secp256k1::musig::MusigAggNonce;
use tokio::sync::mpsc::{self, error::SendError};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{async_trait, Request, Response, Status, Streaming};

#[async_trait]
impl ClementineVerifier for Verifier {
    type NonceGenStream = ReceiverStream<Result<NonceGenResponse, Status>>;
    type DepositSignStream = ReceiverStream<Result<PartialSig, Status>>;

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn get_params(&self, _: Request<Empty>) -> Result<Response<VerifierParams>, Status> {
        let params: VerifierParams = self.try_into()?;

        Ok(Response::new(params))
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn set_verifiers(
        &self,
        request: Request<VerifierPublicKeys>,
    ) -> Result<Response<Empty>, Status> {
        let verifiers_public_keys: Vec<PublicKey> = request.into_inner().try_into()?;

        self.set_verifiers(verifiers_public_keys).await?;

        Ok(Response::new(Empty {}))
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn set_operator(
        &self,
        req: Request<Streaming<OperatorParams>>,
    ) -> Result<Response<Empty>, Status> {
        let mut in_stream = req.into_inner();

        let (
            operator_index,
            collateral_funding_outpoint,
            operator_xonly_pk,
            wallet_reimburse_address,
        ) = parser::operator::parse_details(&mut in_stream).await?;

        let mut operator_kickoff_winternitz_public_keys = Vec::new();
        for _ in 0..self.config.num_kickoffs_per_sequential_collateral_tx
            * self.config.num_sequential_collateral_txs
        {
            operator_kickoff_winternitz_public_keys
                .push(parser::operator::parse_winternitz_public_keys(&mut in_stream).await?);
        }

        self.set_operator(
            operator_index,
            collateral_funding_outpoint,
            operator_xonly_pk,
            wallet_reimburse_address,
            operator_kickoff_winternitz_public_keys,
        )
        .await?;

        Ok(Response::new(Empty {}))
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn set_watchtower(
        &self,
        request: Request<Streaming<WatchtowerParams>>,
    ) -> Result<Response<Empty>, Status> {
        let mut in_stream = request.into_inner();

        let watchtower_id = parser::watchtower::parse_id(&mut in_stream).await?;

        let mut watchtower_winternitz_public_keys = Vec::new();
        for _ in 0..self.config.num_operators
            * self.config.num_sequential_collateral_txs
            * self.config.num_kickoffs_per_sequential_collateral_tx
        {
            watchtower_winternitz_public_keys
                .push(parser::watchtower::parse_winternitz_public_key(&mut in_stream).await?);
        }

        let xonly_pk = parser::watchtower::parse_xonly_pk(&mut in_stream).await?;

        self.set_watchtower(watchtower_id, watchtower_winternitz_public_keys, xonly_pk)
            .await?;

        Ok(Response::new(Empty {}))
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn nonce_gen(
        &self,
        req: Request<NonceGenRequest>,
    ) -> Result<Response<Self::NonceGenStream>, Status> {
        let num_nonces = req.into_inner().num_nonces;

        let (session_id, pub_nonces) = self.nonce_gen(num_nonces).await?;

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
        let verifier = self.clone();

        let (tx, rx) = mpsc::channel(1280);
        let out_stream: Self::DepositSignStream = ReceiverStream::new(rx);

        let (param_tx, mut param_rx) = mpsc::channel(1);
        let (agg_nonce_tx, agg_nonce_rx) = mpsc::channel(1280);

        // Send incoming data to deposit sign job.
        tokio::spawn(async move {
            let params = fetch_next_message_from_stream!(in_stream, params)?;
            let (deposit_outpoint, evm_address, recovery_taproot_address, session_id) = match params
            {
                clementine::verifier_deposit_sign_params::Params::DepositSignFirstParam(
                    deposit_sign_session,
                ) => parser::verifier::parse_deposit_sign_session(
                    deposit_sign_session,
                    verifier.idx,
                )?,
                _ => return Err(Status::invalid_argument("Expected DepositOutpoint")),
            };
            param_tx
                .send((
                    deposit_outpoint,
                    evm_address,
                    recovery_taproot_address,
                    session_id,
                ))
                .await
                .map_err(error::output_stream_ended_prematurely)?;

            while let Some(result) =
                fetch_next_optional_message_from_stream!(&mut in_stream, params)
            {
                let agg_nonce = match result {
                    clementine::verifier_deposit_sign_params::Params::AggNonce(agg_nonce) => {
                        MusigAggNonce::from_slice(agg_nonce.as_slice()).map_err(|e| {
                            BridgeError::RPCParamMalformed("AggNonce".to_string(), e.to_string())
                        })?
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
            let (deposit_outpoint, evm_address, recovery_taproot_address, session_id) = param_rx
                .recv()
                .await
                .ok_or(error::expected_msg_got_none("parameters")())?;

            let mut partial_sig_receiver = verifier
                .deposit_sign(
                    deposit_outpoint,
                    evm_address,
                    recovery_taproot_address,
                    session_id,
                    agg_nonce_rx,
                )
                .await?;

            let mut nonce_idx = 0;
            let num_required_sigs = calculate_num_required_nofn_sigs(&verifier.config);
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
                tracing::debug!(
                    "Verifier {} signed sighash {} of {}",
                    verifier.idx,
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
    ) -> Result<Response<PartialSig>, Status> {
        let mut in_stream = req.into_inner();

        let (sig_tx, sig_rx) = mpsc::channel(1280);
        let (agg_nonce_tx, agg_nonce_rx) = mpsc::channel(1);
        let (operator_sig_tx, operator_sig_rx) = mpsc::channel(1280);

        let params = fetch_next_message_from_stream!(in_stream, params)?;
        let (deposit_outpoint, evm_address, recovery_taproot_address, session_id) = match params {
            Params::DepositSignFirstParam(deposit_sign_session) => {
                parser::verifier::parse_deposit_sign_session(deposit_sign_session, self.idx)?
            }
            _ => Err(Status::internal("Expected DepositOutpoint"))?,
        };

        // Start deposit finalize job.
        let verifier = self.clone();
        let deposit_finalize_handle = tokio::spawn(async move {
            verifier
                .deposit_finalize(
                    deposit_outpoint,
                    evm_address,
                    recovery_taproot_address,
                    session_id,
                    sig_rx,
                    agg_nonce_rx,
                    operator_sig_rx,
                )
                .await
        });

        // Start parsing inputs and send them to deposit finalize job.
        let verifier = self.clone();
        tokio::spawn(async move {
            let num_required_nofn_sigs = calculate_num_required_nofn_sigs(&verifier.config);
            let mut nonce_idx = 0;
            while let Some(sig) =
                parser::verifier::parse_next_deposit_finalize_param_schnorr_sig(&mut in_stream)
                    .await?
            {
                sig_tx
                    .send(sig)
                    .await
                    .map_err(error::output_stream_ended_prematurely)?;

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

            let agg_nonce =
                parser::verifier::parse_deposit_finalize_param_agg_nonce(&mut in_stream).await?;
            agg_nonce_tx
                .send(agg_nonce)
                .await
                .map_err(error::output_stream_ended_prematurely)?;

            let num_required_op_sigs = calculate_num_required_operator_sigs(&verifier.config);
            let num_required_total_op_sigs = num_required_op_sigs * verifier.config.num_operators;
            let mut total_op_sig_count = 0;
            let num_operators = verifier.db.get_operators(None).await?.len();
            for _ in 0..num_operators {
                let mut op_sig_count = 0;

                while let Some(operator_sig) =
                    parser::verifier::parse_next_deposit_finalize_param_schnorr_sig(&mut in_stream)
                        .await?
                {
                    operator_sig_tx
                        .send(operator_sig)
                        .await
                        .map_err(error::output_stream_ended_prematurely)?;

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

        Ok(Response::new(partial_sig.into()))
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn internal_create_signed_tx(
        &self,
        request: Request<TransactionRequest>,
    ) -> Result<Response<RawSignedTx>, Status> {
        let transaction_request = request.into_inner();
        let transaction_data = parse_transaction_request(transaction_request)?;

        let raw_tx = create_and_sign_tx(
            self.db.clone(),
            &self.signer,
            self.config.clone(),
            self.nofn_xonly_pk,
            transaction_data,
        )
        .await?;

        Ok(Response::new(raw_tx))
    }

    async fn set_operator_keys(
        &self,
        request: tonic::Request<super::VerifierOpDepositKeys>,
    ) -> std::result::Result<tonic::Response<super::Empty>, tonic::Status> {
        let data = request.into_inner();
        let (deposit_params, op_keys) = parser::verifier::parse_verifier_op_deposit_keys(data)?;
        self.set_operator_keys(deposit_params, op_keys).await?;
        Ok(Response::new(Empty {}))
    }
}
