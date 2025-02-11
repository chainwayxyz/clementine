use super::clementine::{
    self, clementine_verifier_server::ClementineVerifier, Empty, NonceGenRequest, NonceGenResponse,
    OperatorParams, PartialSig, RawSignedTx, TransactionRequest, VerifierDepositFinalizeParams,
    VerifierDepositSignParams, VerifierParams, VerifierPublicKeys, WatchtowerParams,
};
use super::error::*;
use crate::builder::script::{SpendableScript, WinternitzCommit};
use crate::builder::sighash::SignatureInfo;
use crate::builder::transaction::sign::create_and_sign_tx;
use crate::config::BridgeConfig;
use crate::fetch_next_optional_message_from_stream;
use crate::rpc::clementine::TaggedSignature;
use crate::rpc::parser::parse_transaction_request;
use crate::utils::SECP;
use crate::{
    builder::{
        self,
        address::{derive_challenge_address_from_xonlypk_and_wpk, taproot_builder_with_scripts},
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
    verifier::{NofN, NonceSession, Verifier},
};
use bitcoin::{hashes::Hash, TapTweakHash, Txid};
use bitcoin::{
    secp256k1::{Message, PublicKey},
    ScriptBuf, XOnlyPublicKey,
};
use futures::StreamExt;
use secp256k1::musig::{MusigAggNonce, MusigPubNonce, MusigSecNonce};
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

    /// TODO: This function's contents can be fully moved in to core::verifier.
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn set_verifiers(
        &self,
        req: Request<VerifierPublicKeys>,
    ) -> Result<Response<Empty>, Status> {
        // Check if verifiers are already set
        if self.nofn.read().await.clone().is_some() {
            return Err(Status::internal("Verifiers already set"));
        }

        let verifiers_public_keys: Vec<PublicKey> = req.into_inner().try_into()?;

        let nofn = NofN::new(self.signer.public_key, verifiers_public_keys.clone())?;

        // Save verifiers public keys to db
        self.db
            .set_verifiers_public_keys(None, &verifiers_public_keys)
            .await?;

        // Save the nofn to memory for fast access
        self.nofn.write().await.replace(nofn);

        Ok(Response::new(Empty {}))
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn set_operator(
        &self,
        req: Request<Streaming<OperatorParams>>,
    ) -> Result<Response<Empty>, Status> {
        let mut in_stream = req.into_inner();

        let (operator_idx, collateral_funding_txid, operator_xonly_pk, wallet_reimburse_address) =
            parser::operator::parse_details(&mut in_stream).await?;

        // Save the operator details to the db
        self.db
            .set_operator(
                None,
                operator_idx as i32,
                operator_xonly_pk,
                wallet_reimburse_address.to_string(),
                collateral_funding_txid,
            )
            .await?;

        let mut operator_winternitz_public_keys = Vec::new();
        for _ in 0..self.config.num_kickoffs_per_sequential_collateral_tx
            * self.config.num_sequential_collateral_txs
            * BITVM_CACHE.intermediate_variables.len()
        {
            operator_winternitz_public_keys
                .push(parser::operator::parse_winternitz_public_keys(&mut in_stream).await?);
        }

        self.db
            .set_operator_winternitz_public_keys(
                None,
                operator_idx,
                operator_winternitz_public_keys.clone(),
            )
            .await?;

        let mut operators_challenge_ack_public_hashes = Vec::new();
        for _ in 0..self.config.num_sequential_collateral_txs
            * self.config.num_kickoffs_per_sequential_collateral_tx
            * self.config.num_watchtowers
        {
            operators_challenge_ack_public_hashes
                .push(parser::operator::parse_challenge_ack_public_hash(&mut in_stream).await?);
        }

        for i in 0..self.config.num_sequential_collateral_txs {
            for j in 0..self.config.num_kickoffs_per_sequential_collateral_tx {
                self.db
                    .set_operator_challenge_ack_hashes(
                        None,
                        operator_idx as i32,
                        i as i32,
                        j as i32,
                        &operators_challenge_ack_public_hashes[self.config.num_watchtowers
                            * (i * self.config.num_kickoffs_per_sequential_collateral_tx + j)
                            ..self.config.num_watchtowers
                                * (i * self.config.num_kickoffs_per_sequential_collateral_tx
                                    + j
                                    + 1)],
                    )
                    .await?;
            }
        }
        // Split the winternitz public keys into chunks for every sequential collateral tx and kickoff index.
        // This is done because we need to generate a separate BitVM setup for each collateral tx and kickoff index.
        let chunk_size = BITVM_CACHE.intermediate_variables.len();
        let winternitz_public_keys_chunks =
            operator_winternitz_public_keys.chunks_exact(chunk_size);

        // iterate over the chunks and generate precalculated BitVM Setups
        for (chunk_idx, winternitz_public_keys) in winternitz_public_keys_chunks.enumerate() {
            let sequential_collateral_tx_idx =
                chunk_idx / self.config.num_kickoffs_per_sequential_collateral_tx;
            let kickoff_idx = chunk_idx % self.config.num_kickoffs_per_sequential_collateral_tx;

            let assert_tx_addrs = BITVM_CACHE
                .intermediate_variables
                .iter()
                .enumerate()
                .map(|(idx, (_intermediate_step, intermediate_step_size))| {
                    let winternitz_commit = WinternitzCommit::new(
                        winternitz_public_keys[idx].clone(),
                        operator_xonly_pk,
                        *intermediate_step_size as u32 * 2,
                    );
                    let (assert_tx_addr, _) = builder::address::create_taproot_address(
                        &[winternitz_commit.to_script_buf()],
                        None,
                        self.config.network,
                    );
                    assert_tx_addr.script_pubkey()
                })
                .collect::<Vec<_>>();

            // TODO: Use correct verification key and along with a dummy proof.
            let scripts: Vec<ScriptBuf> = {
                tracing::info!("Replacing disprove scripts");
                utils::replace_disprove_scripts(winternitz_public_keys)
                // let mut bridge_assigner = BridgeAssigner::new_watcher(commits_publickeys);
                // let proof = RawProof::default();
                // let segments = groth16_verify_to_segments(
                //     &mut bridge_assigner,
                //     &proof.public,
                //     &proof.proof,
                //     &proof.vk,
                // );

                // segments
                //     .iter()
                //     .map(|s| s.script.clone().compile())
                //     .collect()
                // vec![bitcoin::script::Builder::new()
                //     .push_opcode(bitcoin::opcodes::all::OP_PUSHNUM_1)
                //     .into_script()]
            };

            let taproot_builder = taproot_builder_with_scripts(&scripts);
            let root_hash = taproot_builder
                .try_into_taptree()
                .expect("taproot builder always builds a full taptree")
                .root_hash();
            let root_hash_bytes = root_hash.to_raw_hash().to_byte_array();

            // Save the public input wots to db along with the root hash
            self.db
                .set_bitvm_setup(
                    None,
                    operator_idx as i32,
                    sequential_collateral_tx_idx as i32,
                    kickoff_idx as i32,
                    assert_tx_addrs,
                    &root_hash_bytes,
                    vec![],
                )
                .await?;
        }

        Ok(Response::new(Empty {}))
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn set_watchtower(
        &self,
        request: Request<Streaming<WatchtowerParams>>,
    ) -> Result<Response<Empty>, Status> {
        let &crate::config::BridgeConfig {
            num_operators,
            num_sequential_collateral_txs,
            num_kickoffs_per_sequential_collateral_tx,
            ..
        } = &self.config;
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

        let required_number_of_pubkeys = num_operators
            * num_sequential_collateral_txs
            * num_kickoffs_per_sequential_collateral_tx;
        if watchtower_winternitz_public_keys.len() != required_number_of_pubkeys {
            return Err(Status::invalid_argument(format!(
                "Request has {} Winternitz public keys but it needs to be {}!",
                watchtower_winternitz_public_keys.len(),
                required_number_of_pubkeys
            )));
        }

        let xonly_pk = parser::watchtower::parse_xonly_pk(&mut in_stream).await?;

        tracing::info!("Verifier receives watchtower index: {:?}", watchtower_id);
        tracing::info!(
            "Verifier receives watchtower xonly public key: {:?}",
            xonly_pk
        );
        for operator_idx in 0..self.config.num_operators {
            let index = operator_idx
                * num_sequential_collateral_txs
                * num_kickoffs_per_sequential_collateral_tx;
            self.db
                .set_watchtower_winternitz_public_keys(
                    None,
                    watchtower_id,
                    operator_idx as u32,
                    watchtower_winternitz_public_keys[index
                        ..index
                            + num_sequential_collateral_txs
                                * num_kickoffs_per_sequential_collateral_tx]
                        .to_vec(),
                )
                .await?;

            // For each saved winternitz public key, derive the challenge address
            let mut watchtower_challenge_addresses = Vec::new();
            for winternitz_pk in watchtower_winternitz_public_keys[index
                ..index
                    + self.config.num_sequential_collateral_txs
                        * self.config.num_kickoffs_per_sequential_collateral_tx]
                .iter()
            {
                let challenge_address = derive_challenge_address_from_xonlypk_and_wpk(
                    &xonly_pk,
                    winternitz_pk,
                    self.config.network,
                )
                .script_pubkey();
                watchtower_challenge_addresses.push(challenge_address);
            }

            // TODO: After precalculating challenge addresses, maybe remove saving winternitz public keys to db
            self.db
                .set_watchtower_challenge_addresses(
                    None,
                    watchtower_id,
                    operator_idx as u32,
                    watchtower_challenge_addresses,
                )
                .await?;
        }

        self.db
            .set_watchtower_xonly_pk(None, watchtower_id, &xonly_pk)
            .await?;

        Ok(Response::new(Empty {}))
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn nonce_gen(
        &self,
        req: Request<NonceGenRequest>,
    ) -> Result<Response<Self::NonceGenStream>, Status> {
        let num_nonces = req.into_inner().num_nonces as usize;
        let (sec_nonces, pub_nonces): (Vec<MusigSecNonce>, Vec<MusigPubNonce>) = (0..num_nonces)
            .map(|_| {
                // nonce pair needs keypair and a rng
                let (sec_nonce, pub_nonce) = musig2::nonce_pair(
                    &self.signer.keypair,
                    &mut bitcoin::secp256k1::rand::thread_rng(),
                )?;
                Ok((sec_nonce, pub_nonce))
            })
            .collect::<Result<Vec<(MusigSecNonce, MusigPubNonce)>, BridgeError>>()?
            .into_iter()
            .unzip(); // TODO: fix extra copies

        let session = NonceSession { nonces: sec_nonces };

        // save the session
        let session_id = {
            let all_sessions = &mut *self.nonces.lock().await;
            let session_id = all_sessions.cur_id;
            all_sessions.sessions.insert(session_id, session);
            all_sessions.cur_id += 1;
            session_id
        };

        let nonce_gen_first_response = clementine::NonceGenFirstResponse {
            id: session_id,
            num_nonces: num_nonces as u32,
        };

        let (tx, rx) = mpsc::channel(pub_nonces.len() + 1);
        tokio::spawn(async move {
            // First send the session id
            let session_id: NonceGenResponse = nonce_gen_first_response.into();
            tx.send(Ok(session_id)).await?;

            // Then send the public nonces
            for pub_nonce in &pub_nonces[..] {
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
        let error_tx = tx.clone();

        let handle = tokio::spawn(async move {
            let params = fetch_next_message_from_stream!(in_stream, params)?;

            let (deposit_outpoint, evm_address, recovery_taproot_address, session_id) = match params
            {
                clementine::verifier_deposit_sign_params::Params::DepositSignFirstParam(
                    deposit_sign_session,
                ) => parser::verifier::parse_deposit_params(deposit_sign_session, verifier.idx)?,
                _ => return Err(Status::invalid_argument("Expected DepositOutpoint")),
            };

            let mut session_map = verifier.nonces.lock().await;
            let session = session_map.sessions.get_mut(&session_id).ok_or_else(|| {
                Status::internal(format!("Could not find session id {session_id}"))
            })?;
            session.nonces.reverse();

            let mut nonce_idx: usize = 0;

            let mut sighash_stream = pin!(create_nofn_sighash_stream(
                verifier.db,
                verifier.config.clone(),
                deposit_outpoint,
                evm_address,
                recovery_taproot_address,
                verifier.nofn_xonly_pk,
            ));
            let num_required_sigs = calculate_num_required_nofn_sigs(&verifier.config);

            assert!(
                num_required_sigs + 1 == session.nonces.len(),
                "Expected nonce count to be num_required_sigs + 1 (movetx)"
            );

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

                let sighash = sighash_stream
                    .next()
                    .await
                    .ok_or(Status::internal("No sighash received"))??;
                tracing::debug!("Verifier {} found sighash: {:?}", verifier.idx, sighash);

                let nonce = session.nonces.pop().expect("No nonce available");
                let partial_sig = musig2::partial_sign(
                    verifier.config.verifiers_public_keys.clone(),
                    None,
                    nonce,
                    agg_nonce,
                    verifier.signer.keypair,
                    Message::from_digest(*sighash.0.as_byte_array()),
                )?;

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
            // Drop all the nonces except the last one, to avoid reusing the nonces.
            let last_nonce = session
                .nonces
                .pop()
                .ok_or(Status::internal("No last nonce available"))?;
            session.nonces.clear();
            session.nonces.push(last_nonce);

            Ok::<(), Status>(())
        });

        // Background task to handle the error case where the background task fails, notifies caller
        tokio::spawn(async move {
            if let Ok(Err(bg_err)) = handle.await {
                let ret_res = error_tx.send(Err(bg_err)).await;
                if let Err(SendError(Err(e))) = ret_res {
                    tracing::error!("deposit_sign background task failed and the return stream ended prematurely:\n\n Background task error: {e}");
                }
            }
        });

        let out_stream: Self::DepositSignStream = ReceiverStream::new(rx);
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

        let (deposit_outpoint, evm_address, recovery_taproot_address, session_id) = match params {
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
            self.config.user_takes_after,
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
        for (operator_idx, (op_xonly_pk, reimburse_addr, collateral_txid)) in
            operators_data.iter().enumerate()
        {
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
                reimburse_addr.clone(),
                *op_xonly_pk,
                self.config.clone(),
                deposit_outpoint,
                evm_address,
                recovery_taproot_address.clone(),
                self.nofn_xonly_pk,
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

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn create_signed_tx(
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
}
