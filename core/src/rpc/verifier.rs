use super::clementine::{
    self, clementine_verifier_server::ClementineVerifier, Empty, NonceGenRequest, NonceGenResponse,
    OperatorParams, PartialSig, VerifierDepositFinalizeParams, VerifierDepositSignParams,
    VerifierParams, VerifierPublicKeys, WatchtowerParams,
};
use super::error::*;
use crate::builder::sighash::SignatureInfo;
use crate::config::BridgeConfig;
use crate::fetch_next_optional_message_from_stream;
use crate::rpc::clementine::TaggedSignature;
use crate::utils::SECP;
use crate::{
    builder::{
        sighash::{
            calculate_num_required_nofn_sigs, calculate_num_required_nofn_sigs_per_kickoff,
            calculate_num_required_operator_sigs, calculate_num_required_operator_sigs_per_kickoff,
            create_nofn_sighash_stream, create_operator_sighash_stream,
        },
        transaction::create_move_to_vault_txhandler,
    },
    errors::BridgeError,
    fetch_next_message_from_stream,
    musig2::{self},
    rpc::parser::{self},
    utils::{self, BITVM_CACHE},
    verifier::Verifier,
};
use bitcoin::{hashes::Hash, Amount, TapTweakHash, Txid};
use bitcoin::{
    secp256k1::{Message, PublicKey},
    XOnlyPublicKey,
};
use futures::StreamExt;
use secp256k1::musig::MusigAggNonce;
use std::pin::pin;
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

        let (operator_index, collateral_funding_txid, operator_xonly_pk, wallet_reimburse_address) =
            parser::operator::parse_details(&mut in_stream).await?;

        let mut operator_winternitz_public_keys = Vec::new();
        for _ in 0..self.config.num_kickoffs_per_sequential_collateral_tx
            * self.config.num_sequential_collateral_txs
            * BITVM_CACHE.intermediate_variables.len()
        {
            operator_winternitz_public_keys
                .push(parser::operator::parse_winternitz_public_keys(&mut in_stream).await?);
        }

        let mut operators_challenge_ack_public_hashes = Vec::new();
        for _ in 0..self.config.num_sequential_collateral_txs
            * self.config.num_kickoffs_per_sequential_collateral_tx
            * self.config.num_watchtowers
        {
            operators_challenge_ack_public_hashes
                .push(parser::operator::parse_challenge_ack_public_hash(&mut in_stream).await?);
        }

        self.set_operator(
            operator_index,
            collateral_funding_txid,
            operator_xonly_pk,
            wallet_reimburse_address,
            operator_winternitz_public_keys,
            operators_challenge_ack_public_hashes,
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
            let (
                deposit_outpoint,
                evm_address,
                recovery_taproot_address,
                user_takes_after,
                session_id,
            ) = match params {
                clementine::verifier_deposit_sign_params::Params::DepositSignFirstParam(
                    deposit_sign_session,
                ) => parser::verifier::parse_deposit_params(deposit_sign_session, verifier.idx)?,
                _ => return Err(Status::invalid_argument("Expected DepositOutpoint")),
            };
            param_tx
                .send((
                    deposit_outpoint,
                    evm_address,
                    recovery_taproot_address,
                    user_takes_after,
                    session_id,
                ))
                .await
                .expect("TODO");

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

                agg_nonce_tx.send(agg_nonce).await.expect("TODO");
            }
            Ok(())
        });

        // Start partial sig job and return partial sig responses.
        tokio::spawn(async move {
            let (
                deposit_outpoint,
                evm_address,
                recovery_taproot_address,
                user_takes_after,
                session_id,
            ) = param_rx.recv().await.expect("TODO");

            let mut partial_sig_receiver = verifier
                .deposit_sign(
                    deposit_outpoint,
                    evm_address,
                    recovery_taproot_address,
                    user_takes_after,
                    session_id,
                    agg_nonce_rx,
                )
                .await?;

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
        use clementine::verifier_deposit_finalize_params::Params;
        let mut in_stream = req.into_inner();

        let params = fetch_next_message_from_stream!(in_stream, params)?;

        let (deposit_outpoint, evm_address, recovery_taproot_address, user_takes_after, session_id) =
            match params {
                Params::DepositSignFirstParam(deposit_sign_session) => {
                    parser::verifier::parse_deposit_params(deposit_sign_session, self.idx)?
                }
                _ => Err(Status::internal("Expected DepositOutpoint"))?,
            };

        let mut sighash_stream = pin!(create_nofn_sighash_stream(
            self.db.clone(),
            self.config.clone(),
            deposit_outpoint,
            evm_address,
            recovery_taproot_address.clone(),
            self.nofn_xonly_pk,
            user_takes_after,
            Amount::from_sat(200_000_000), // TODO: Fix this.
            6,
            100,
            self.config.bridge_amount_sats,
            self.config.network,
        ));

        let num_required_nofn_sigs = calculate_num_required_nofn_sigs(&self.config);
        let num_required_nofn_sigs_per_kickoff =
            calculate_num_required_nofn_sigs_per_kickoff(&self.config);
        let num_required_op_sigs = calculate_num_required_operator_sigs(&self.config);
        let num_required_op_sigs_per_kickoff = calculate_num_required_operator_sigs_per_kickoff();
        let &BridgeConfig {
            num_operators,
            num_sequential_collateral_txs,
            num_kickoffs_per_sequential_collateral_tx,
            ..
        } = &self.config;
        let mut verified_sigs = vec![
            vec![
                vec![
                    Vec::<TaggedSignature>::with_capacity(
                        num_required_nofn_sigs_per_kickoff + num_required_op_sigs_per_kickoff
                    );
                    num_kickoffs_per_sequential_collateral_tx
                ];
                num_sequential_collateral_txs
            ];
            num_operators
        ];

        let mut nonce_idx: usize = 0;

        while let Some(sig) =
            parser::verifier::parse_next_deposit_finalize_param_schnorr_sig(&mut in_stream).await?
        {
            let sighash = sighash_stream
                .next()
                .await
                .ok_or_else(sighash_stream_ended_prematurely)?
                .map_err(Into::into)
                .map_err(sighash_stream_failed)?;

            tracing::debug!("Verifying Final Signature");
            utils::SECP
                .verify_schnorr(&sig, &Message::from(sighash.0), &self.nofn_xonly_pk)
                .map_err(|x| {
                    Status::internal(format!(
                        "Nofn Signature {} Verification Failed: {}.",
                        nonce_idx + 1,
                        x
                    ))
                })?;
            let &SignatureInfo {
                operator_idx,
                sequential_collateral_idx,
                kickoff_utxo_idx,
                signature_id,
            } = &sighash.1;
            let tagged_sig = TaggedSignature {
                signature: sig.serialize().to_vec(),
                signature_id: Some(signature_id),
            };
            verified_sigs[operator_idx][sequential_collateral_idx][kickoff_utxo_idx]
                .push(tagged_sig);
            tracing::debug!("Final Signature Verified");

            nonce_idx += 1;
            if nonce_idx == num_required_nofn_sigs {
                break;
            }
        }

        if nonce_idx != num_required_nofn_sigs {
            return Err(Status::internal(format!(
                "Not received enough nofn signatures. Needed: {}, received: {}",
                num_required_nofn_sigs, nonce_idx
            )));
        }

        // Generate partial signature for move transaction
        let move_txhandler = create_move_to_vault_txhandler(
            deposit_outpoint,
            evm_address,
            &recovery_taproot_address,
            self.nofn_xonly_pk,
            user_takes_after,
            self.config.bridge_amount_sats,
            self.config.network,
        )?;

        let move_tx_sighash = move_txhandler.calculate_script_spend_sighash_indexed(
            0,
            0,
            bitcoin::TapSighashType::Default,
        )?;

        let agg_nonce =
            parser::verifier::parse_deposit_finalize_param_agg_nonce(&mut in_stream).await?;

        let movetx_secnonce = {
            let mut session_map = self.nonces.lock().await;
            let session = session_map.sessions.get_mut(&session_id).ok_or_else(|| {
                Status::internal(format!(
                    "could not find session with id {} in session cache",
                    session_id
                ))
            })?;
            session
                .nonces
                .pop()
                .ok_or_else(|| Status::internal("No move tx secnonce in session"))?
        };

        let num_required_total_op_sigs = num_required_op_sigs * self.config.num_operators;
        let mut total_op_sig_count = 0;

        // get operator data
        let operators_data: Vec<(XOnlyPublicKey, bitcoin::Address, Txid)> =
            self.db.get_operators(None).await?;

        // get signatures of operators and verify them
        for (operator_idx, (op_xonly_pk, _, collateral_txid)) in operators_data.iter().enumerate() {
            let mut op_sig_count = 0;
            // tweak the operator xonly public key with None (because merkle root is empty as operator utxos have no scripts)
            let scalar = TapTweakHash::from_key_and_tweak(*op_xonly_pk, None).to_scalar();
            let tweaked_op_xonly_pk = op_xonly_pk
                .add_tweak(&SECP, &scalar)
                .map_err(|x| {
                    Status::internal(format!("Failed to tweak operator xonly public key: {}", x))
                })?
                .0;
            // generate the sighash stream for operator
            let mut sighash_stream = pin!(create_operator_sighash_stream(
                self.db.clone(),
                operator_idx,
                *collateral_txid,
                *op_xonly_pk,
                self.config.clone(),
                deposit_outpoint,
                evm_address,
                recovery_taproot_address.clone(),
                self.nofn_xonly_pk,
                user_takes_after,
                Amount::from_sat(200_000_000), // TODO: Fix this.
                6,
                100,
                self.config.bridge_amount_sats,
                self.config.network,
            ));
            while let Some(operator_sig) =
                parser::verifier::parse_next_deposit_finalize_param_schnorr_sig(&mut in_stream)
                    .await?
            {
                let sighash = sighash_stream
                    .next()
                    .await
                    .ok_or_else(sighash_stream_ended_prematurely)??;

                utils::SECP
                    .verify_schnorr(
                        &operator_sig,
                        &Message::from(sighash.0),
                        &tweaked_op_xonly_pk,
                    )
                    .map_err(|x| {
                        Status::internal(format!(
                            "Operator {} Signature {}: verification failed: {}.",
                            operator_idx,
                            op_sig_count + 1,
                            x
                        ))
                    })?;

                let &SignatureInfo {
                    operator_idx,
                    sequential_collateral_idx,
                    kickoff_utxo_idx,
                    signature_id,
                } = &sighash.1;
                let tagged_sig = TaggedSignature {
                    signature: operator_sig.serialize().to_vec(),
                    signature_id: Some(signature_id),
                };
                verified_sigs[operator_idx][sequential_collateral_idx][kickoff_utxo_idx]
                    .push(tagged_sig);

                op_sig_count += 1;
                total_op_sig_count += 1;
                if op_sig_count == num_required_op_sigs {
                    break;
                }
            }
        }

        if total_op_sig_count != num_required_total_op_sigs {
            return Err(Status::internal(format!(
                "Not enough operator signatures. Needed: {}, received: {}",
                num_required_total_op_sigs, total_op_sig_count
            )));
        }

        // sign move tx and save everything to db if everything is correct
        let partial_sig: PartialSig = musig2::partial_sign(
            self.config.verifiers_public_keys.clone(),
            None,
            movetx_secnonce,
            agg_nonce,
            self.signer.keypair,
            Message::from_digest(move_tx_sighash.to_byte_array()),
        )?
        .into();

        // Deposit is not actually finalized here, its only finalized after the aggregator gets all the partial sigs and checks the aggregated sig
        // TODO: It can create problems if the deposit fails at the end by some verifier not sending movetx partial sig, but we still added sigs to db
        for (operator_idx, operator_sigs) in verified_sigs.into_iter().enumerate() {
            for (seq_idx, op_sequential_sigs) in operator_sigs.into_iter().enumerate() {
                for (kickoff_idx, kickoff_sigs) in op_sequential_sigs.into_iter().enumerate() {
                    self.db
                        .set_deposit_signatures(
                            None,
                            deposit_outpoint,
                            operator_idx,
                            seq_idx,
                            kickoff_idx,
                            kickoff_sigs,
                        )
                        .await?;
                }
            }
        }

        Ok(Response::new(partial_sig))
    }
}
