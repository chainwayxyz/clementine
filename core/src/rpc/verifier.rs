use super::clementine::{
    self, clementine_verifier_server::ClementineVerifier, nonce_gen_response, Empty,
    NonceGenRequest, NonceGenResponse, OperatorParams, PartialSig, VerifierDepositFinalizeParams,
    VerifierDepositSignParams, VerifierParams, VerifierPublicKeys, WatchtowerParams,
};
use crate::{
    builder::sighash::{calculate_num_required_nofn_sigs, create_nofn_sighash_stream},
    builder::transaction::create_move_to_vault_txhandler,
    builder::{self, address::taproot_builder_with_scripts},
    errors::BridgeError,
    musig2::{self},
    utils,
    verifier::{NofN, NonceSession, Verifier},
    EVMAddress,
};
use bitcoin::{address::NetworkUnchecked, hashes::Hash, Amount, TapTweakHash, Txid};
use bitcoin::{
    secp256k1::{schnorr, Message, PublicKey},
    ScriptBuf, XOnlyPublicKey,
};
use bitvm::signatures::{
    signing_winternitz::{generate_winternitz_checksig_leave_variable, WinternitzPublicKey},
    winternitz,
};

use crate::builder::sighash::{
    calculate_num_required_operator_sigs, create_operator_sighash_stream,
};
use crate::utils::SECP;
use futures::StreamExt;
use secp256k1::musig::{MusigAggNonce, MusigPubNonce, MusigSecNonce};
use std::collections::BTreeMap;
use std::{pin::pin, str::FromStr};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{async_trait, Request, Response, Status, Streaming};

fn get_deposit_params(
    deposit_sign_session: clementine::DepositSignSession,
    verifier_idx: usize,
) -> Result<
    (
        bitcoin::OutPoint,
        EVMAddress,
        bitcoin::Address<NetworkUnchecked>,
        u16,
        u32,
    ),
    Status,
> {
    let deposit_params = deposit_sign_session
        .deposit_params
        .ok_or(Status::invalid_argument("No deposit outpoint received"))?;
    let deposit_outpoint: bitcoin::OutPoint = deposit_params
        .deposit_outpoint
        .ok_or(Status::invalid_argument("No deposit outpoint received"))?
        .try_into()?;
    let evm_address: EVMAddress = deposit_params.evm_address.try_into().unwrap();
    let recovery_taproot_address = deposit_params
        .recovery_taproot_address
        .parse::<bitcoin::Address<_>>()
        .map_err(|e| Status::internal(e.to_string()))?;
    let user_takes_after = deposit_params.user_takes_after;

    let session_id = deposit_sign_session.nonce_gen_first_responses[verifier_idx].id;
    Ok((
        deposit_outpoint,
        evm_address,
        recovery_taproot_address,
        u16::try_from(user_takes_after).map_err(|e| {
            Status::invalid_argument(format!(
                "user_takes_after is too big, failed to convert: {}",
                e
            ))
        })?,
        session_id,
    ))
}
#[async_trait]
impl ClementineVerifier for Verifier {
    type NonceGenStream = ReceiverStream<Result<NonceGenResponse, Status>>;
    type DepositSignStream = ReceiverStream<Result<PartialSig, Status>>;

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    #[allow(clippy::blocks_in_conditions)]
    async fn get_params(&self, _: Request<Empty>) -> Result<Response<VerifierParams>, Status> {
        let public_key = self.signer.public_key.serialize().to_vec();

        let params = VerifierParams {
            id: self.idx as u32,
            public_key,
            num_verifiers: self.config.num_verifiers as u32,
            num_watchtowers: self.config.num_watchtowers as u32,
            num_operators: self.config.num_operators as u32,
            num_time_txs: self.config.num_time_txs as u32,
        };

        Ok(Response::new(params))
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    #[allow(clippy::blocks_in_conditions)]
    async fn set_verifiers(
        &self,
        req: Request<VerifierPublicKeys>,
    ) -> Result<Response<Empty>, Status> {
        // Check if verifiers are already set
        if self.nofn.read().await.clone().is_some() {
            return Err(Status::internal("Verifiers already set"));
        }

        // Extract the public keys from the request
        let verifiers_public_keys: Vec<PublicKey> = req
            .into_inner()
            .verifier_public_keys
            .iter()
            .map(|pk| PublicKey::from_slice(pk).unwrap())
            .collect();

        let nofn = NofN::new(self.signer.public_key, verifiers_public_keys.clone());

        // Save verifiers public keys to db
        self.db
            .save_verifier_public_keys(None, &verifiers_public_keys)
            .await?;

        // Save the nofn to memory for fast access
        self.nofn.write().await.replace(nofn);

        Ok(Response::new(Empty {}))
    }

    // #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    #[allow(clippy::blocks_in_conditions)]
    async fn set_operator(&self, req: Request<OperatorParams>) -> Result<Response<Empty>, Status> {
        let operator_params = req.into_inner();

        let operator_config = operator_params
            .operator_details
            .ok_or(BridgeError::Error("No operator details".to_string()))?;

        let operator_xonly_pk = XOnlyPublicKey::from_str(&operator_config.xonly_pk)
            .map_err(|_| BridgeError::Error("Invalid xonly public key".to_string()))?;

        // Save the operator details to the db
        self.db
            .set_operator(
                None,
                operator_config.operator_idx as i32,
                operator_xonly_pk,
                operator_config.wallet_reimburse_address,
                Txid::from_byte_array(
                    operator_config
                        .collateral_funding_txid
                        .clone()
                        .try_into()
                        .unwrap(),
                ),
            )
            .await?;

        // Convert RPC type into BitVM type.
        let operator_winternitz_public_keys = operator_params
            .winternitz_pubkeys
            .into_iter()
            .map(|wpk| Ok(wpk.to_bitvm()))
            .collect::<Result<Vec<_>, BridgeError>>()?;

        self.db
            .save_operator_winternitz_public_keys(
                None,
                operator_config.operator_idx,
                operator_winternitz_public_keys.clone(),
            )
            .await?;
        // Split the winternitz public keys into chunks for every sequential collateral tx and kickoff index.
        // This is done because we need to generate a separate BitVM setup for each collateral tx and kickoff index.
        let chunk_size = utils::ALL_BITVM_INTERMEDIATE_VARIABLES.len();
        let winternitz_public_keys_chunks =
            operator_winternitz_public_keys.chunks_exact(chunk_size);

        // iterate over the chunks and generate precalculated BitVM Setups
        for (chunk_idx, winternitz_public_keys) in winternitz_public_keys_chunks.enumerate() {
            let time_tx_idx = chunk_idx / self.config.num_kickoffs_per_timetx;
            let kickoff_idx = chunk_idx % self.config.num_kickoffs_per_timetx;

            let mut public_input_wots = vec![];
            // Generate precalculated BitVM Setups
            let _commits_publickeys = utils::ALL_BITVM_INTERMEDIATE_VARIABLES
                .iter()
                .enumerate()
                .map(|(idx, (intermediate_step, intermediate_step_size))| {
                    let winternitz_pk: WinternitzPublicKey = WinternitzPublicKey {
                        public_key: winternitz_public_keys[idx].clone(),
                        parameters: winternitz::Parameters::new(
                            *intermediate_step_size as u32 * 2,
                            4,
                        ),
                    };

                    if intermediate_step == "scalar_1" {
                        // scalar_1 is the public input.
                        public_input_wots = winternitz_pk.public_key.clone();
                    }

                    Ok((intermediate_step.clone(), winternitz_pk))
                })
                .collect::<Result<BTreeMap<_, _>, BridgeError>>()?;

            let assert_tx_addrs = utils::ALL_BITVM_INTERMEDIATE_VARIABLES
                .iter()
                .enumerate()
                .map(|(idx, (_intermediate_step, intermediate_step_size))| {
                    let script = generate_winternitz_checksig_leave_variable(
                        &WinternitzPublicKey {
                            public_key: winternitz_public_keys[idx].clone(),
                            parameters: winternitz::Parameters::new(
                                *intermediate_step_size as u32 * 2,
                                4,
                            ),
                        },
                        *intermediate_step_size,
                    )
                    .compile();
                    let (assert_tx_addr, _) = builder::address::create_taproot_address(
                        &[script.clone()],
                        None,
                        self.config.network,
                    );
                    assert_tx_addr.script_pubkey()
                })
                .collect::<Vec<_>>();

            // TODO: Use correct verification key and along with a dummy proof.
            let scripts: Vec<ScriptBuf> = {
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
                vec![bitcoin::script::Builder::new()
                    .push_opcode(bitcoin::opcodes::all::OP_PUSHNUM_1)
                    .into_script()]
            };

            let taproot_builder = taproot_builder_with_scripts(&scripts);
            let root_hash = taproot_builder.try_into_taptree().unwrap().root_hash();
            let root_hash_bytes = root_hash.to_raw_hash().to_byte_array();

            // Save the public input wots to db along with the root hash
            self.db
                .save_bitvm_setup(
                    None,
                    operator_config.operator_idx as i32,
                    time_tx_idx as i32,
                    kickoff_idx as i32,
                    assert_tx_addrs,
                    &root_hash_bytes,
                    public_input_wots,
                )
                .await?;
        }

        Ok(Response::new(Empty {}))
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    #[allow(clippy::blocks_in_conditions)]
    async fn set_watchtower(
        &self,
        request: Request<WatchtowerParams>,
    ) -> Result<Response<Empty>, Status> {
        let watchtower_params = request.into_inner();

        // Convert RPC type into BitVM type.
        let watchtower_winternitz_public_keys = watchtower_params
            .winternitz_pubkeys
            .into_iter()
            .map(|wpk| Ok(wpk.to_bitvm()))
            .collect::<Result<Vec<_>, BridgeError>>()?;

        let required_number_of_pubkeys = self.config.num_operators
            * self.config.num_time_txs
            * self.config.num_kickoffs_per_timetx;
        if watchtower_winternitz_public_keys.len() != required_number_of_pubkeys {
            return Err(Status::invalid_argument(format!(
                "Request has {} Winternitz public keys but it needs to be {}!",
                watchtower_winternitz_public_keys.len(),
                required_number_of_pubkeys
            )));
        }

        for operator_idx in 0..self.config.num_operators {
            let index =
                operator_idx * self.config.num_time_txs * self.config.num_kickoffs_per_timetx;
            self.db
                .save_watchtower_winternitz_public_keys(
                    None,
                    watchtower_params.watchtower_id,
                    operator_idx as u32,
                    watchtower_winternitz_public_keys[index
                        ..index + self.config.num_time_txs * self.config.num_kickoffs_per_timetx]
                        .to_vec(),
                )
                .await?;
        }

        let xonly_pk = XOnlyPublicKey::from_slice(&watchtower_params.xonly_pk).map_err(|_| {
            BridgeError::RPCParamMalformed("watchtower.xonly_pk", "Invalid xonly key".to_string())
        })?;
        self.db
            .save_watchtower_xonly_pk(None, watchtower_params.watchtower_id, &xonly_pk)
            .await?;

        Ok(Response::new(Empty {}))
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    #[allow(clippy::blocks_in_conditions)]
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
                )
                .unwrap();
                (sec_nonce, pub_nonce)
            })
            .unzip();

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

        // now stream the nonces
        let (tx, rx) = mpsc::channel(1280);
        tokio::spawn(async move {
            // First send the session id
            let response = NonceGenResponse {
                response: Some(nonce_gen_response::Response::FirstResponse(
                    nonce_gen_first_response,
                )),
            };
            tx.send(Ok(response)).await.unwrap();

            // Then send the public nonces
            for pub_nonce in &pub_nonces[..] {
                let response = NonceGenResponse {
                    response: Some(nonce_gen_response::Response::PubNonce(
                        pub_nonce.serialize().to_vec(),
                    )),
                };
                tx.send(Ok(response)).await.unwrap();
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn deposit_sign(
        &self,
        req: Request<Streaming<VerifierDepositSignParams>>,
    ) -> Result<Response<Self::DepositSignStream>, Status> {
        let mut in_stream = req.into_inner();

        let (tx, rx) = mpsc::channel(1280);

        tracing::info!("Received deposit sign request");

        let verifier = self.clone();

        tokio::spawn(async move {
            let first_message = in_stream
                .message()
                .await
                .unwrap()
                .ok_or(Status::internal("No first message received"))
                .unwrap();

            // Parse the first message
            let params = first_message
                .params
                .ok_or(Status::internal("No deposit outpoint received"))
                .unwrap();

            let (
                deposit_outpoint,
                evm_address,
                recovery_taproot_address,
                user_takes_after,
                session_id,
            ) = match params {
                clementine::verifier_deposit_sign_params::Params::DepositSignFirstParam(
                    deposit_sign_session,
                ) => get_deposit_params(deposit_sign_session, verifier.idx).unwrap(),
                _ => panic!("Expected DepositOutpoint"),
            };

            let mut session_map = verifier.nonces.lock().await;
            let session = session_map
                .sessions
                .get_mut(&session_id)
                .ok_or_else(|| Status::internal(format!("Could not find session id {session_id}")))
                .unwrap();
            session.nonces.reverse();

            let mut nonce_idx: usize = 0;

            let mut sighash_stream = pin!(create_nofn_sighash_stream(
                verifier.db,
                verifier.config.clone(),
                deposit_outpoint,
                evm_address,
                recovery_taproot_address,
                verifier.nofn_xonly_pk,
                user_takes_after,
                Amount::from_sat(200_000_000), // TODO: Fix this.
                6,
                100,
                verifier.config.bridge_amount_sats,
                verifier.config.network,
            ));
            let num_required_sigs = calculate_num_required_nofn_sigs(&verifier.config);

            assert!(
                num_required_sigs + 1 == session.nonces.len(),
                "Expected nonce count to be num_required_sigs + 1 (movetx)"
            );

            while let Some(result) = in_stream.message().await.unwrap() {
                let agg_nonce = match result
                    .params
                    .ok_or(Status::internal("No agg nonce received"))
                    .unwrap()
                {
                    clementine::verifier_deposit_sign_params::Params::AggNonce(agg_nonce) => {
                        MusigAggNonce::from_slice(agg_nonce.as_slice()).unwrap()
                    }
                    _ => panic!("Expected AggNonce"),
                };

                let sighash = sighash_stream.next().await.unwrap().unwrap();
                tracing::debug!("Verifier {} found sighash: {:?}", verifier.idx, sighash);

                let nonce = session.nonces.pop().expect("No nonce available");
                let partial_sig = musig2::partial_sign(
                    verifier.config.verifiers_public_keys.clone(),
                    None,
                    nonce,
                    agg_nonce,
                    verifier.signer.keypair,
                    Message::from_digest(*sighash.as_byte_array()),
                )
                .unwrap();

                tx.send(Ok(PartialSig {
                    partial_sig: partial_sig.serialize().to_vec(),
                }))
                .await
                .unwrap();

                nonce_idx += 1;
                if nonce_idx == num_required_sigs {
                    break;
                }
            }

            // Drop all the nonces except the last one, to avoid reusing the nonces.
            let last_nonce = session.nonces.pop().unwrap();
            session.nonces.clear();
            session.nonces.push(last_nonce);
        });

        let out_stream: Self::DepositSignStream = ReceiverStream::new(rx);
        Ok(Response::new(out_stream))
    }

    /// Function to finalize the deposit. Verifier will check the validity of the both nofn signatures and
    /// operator signatures. It will receive data from the stream in this order -> nofn sigs, movetx agg nonce, operator sigs.
    /// If everything is correct, it will partially sign the move tx and send it to aggregator.
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    #[allow(clippy::blocks_in_conditions)]
    async fn deposit_finalize(
        &self,
        req: Request<Streaming<VerifierDepositFinalizeParams>>,
    ) -> Result<Response<PartialSig>, Status> {
        use clementine::verifier_deposit_finalize_params::Params;
        let mut in_stream = req.into_inner();

        let first_message = in_stream
            .message()
            .await?
            .ok_or(Status::internal("No first message received"))?;

        // Parse the first message
        let (deposit_outpoint, evm_address, recovery_taproot_address, user_takes_after, session_id) =
            match first_message
                .params
                .ok_or(Status::internal("No deposit outpoint received"))?
            {
                Params::DepositSignFirstParam(deposit_sign_session) => {
                    get_deposit_params(deposit_sign_session, self.idx)?
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
        let mut verified_sigs = Vec::with_capacity(num_required_nofn_sigs);
        let mut nonce_idx: usize = 0;

        while let Some(result) = in_stream.message().await.unwrap() {
            let sighash = sighash_stream.next().await.unwrap().unwrap();
            let final_sig = result
                .params
                .ok_or(Status::internal("No final sig received"))?;
            let final_sig = match final_sig {
                Params::SchnorrSig(final_sig) => {
                    schnorr::Signature::from_slice(&final_sig).unwrap()
                }
                _ => return Err(Status::internal("Expected FinalSig")),
            };

            tracing::debug!("Verifying Final Signature");
            utils::SECP
                .verify_schnorr(&final_sig, &Message::from(sighash), &self.nofn_xonly_pk)
                .map_err(|x| {
                    Status::internal(format!(
                        "Nofn Signature {} Verification Failed: {}.",
                        nonce_idx + 1,
                        x
                    ))
                })?;

            verified_sigs.push(final_sig);
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
        let mut move_txhandler = create_move_to_vault_txhandler(
            deposit_outpoint,
            evm_address,
            &recovery_taproot_address,
            self.nofn_xonly_pk,
            user_takes_after,
            self.config.bridge_amount_sats,
            self.config.network,
        );

        let move_tx_sighash = move_txhandler.calculate_script_spend_sighash(0, 0, None)?;

        let agg_nonce = match in_stream.message().await.unwrap().unwrap().params.unwrap() {
            Params::MoveTxAggNonce(aggnonce) => MusigAggNonce::from_slice(&aggnonce)
                .map_err(|e| Status::internal(format!("Invalid aggregate nonce: {}", e)))?,
            _ => Err(Status::internal("Expected MoveTxAggNonce"))?,
        };

        let movetx_secnonce = {
            let mut session_map = self.nonces.lock().await;
            let session = session_map.sessions.get_mut(&session_id).unwrap();
            session
                .nonces
                .pop()
                .ok_or_else(|| Status::internal("No move tx secnonce in session"))?
        };

        let mut op_deposit_sigs: Vec<Vec<schnorr::Signature>> = verified_sigs
            .chunks_exact(verified_sigs.len() / self.config.num_operators)
            .map(|chunk| chunk.to_vec())
            .collect();

        let num_required_op_sigs = calculate_num_required_operator_sigs(&self.config);
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
            while let Some(result) = in_stream.message().await? {
                let sighash = sighash_stream.next().await.unwrap()?;
                let operator_sig = result
                    .params
                    .ok_or(Status::internal("No operator sig received"))?;
                let final_sig = match operator_sig {
                    Params::SchnorrSig(final_sig) => {
                        schnorr::Signature::from_slice(&final_sig).unwrap()
                    }
                    _ => {
                        return Err(Status::internal(format!(
                            "Expected Operator Sig, got: {:?}",
                            operator_sig
                        )))
                    }
                };

                utils::SECP
                    .verify_schnorr(&final_sig, &Message::from(sighash), &tweaked_op_xonly_pk)
                    .map_err(|x| {
                        Status::internal(format!(
                            "Operator {} Signature {} Verification Failed: {}.",
                            operator_idx,
                            op_sig_count + 1,
                            x
                        ))
                    })?;

                op_deposit_sigs[operator_idx].push(final_sig);

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
        let partial_sig = musig2::partial_sign(
            self.config.verifiers_public_keys.clone(),
            None,
            movetx_secnonce,
            agg_nonce,
            self.signer.keypair,
            Message::from_digest(move_tx_sighash.to_byte_array()),
        )?;

        // TODO: deposit is not actually finalized here, its only finalized after the aggregator gets all the correct partial sigs
        for (i, window) in op_deposit_sigs.into_iter().enumerate() {
            self.db
                .save_deposit_signatures(None, deposit_outpoint, i as u32, window)
                .await?;
        }

        tracing::info!("Deposit finalized, returning partial sig");
        Ok(Response::new(PartialSig {
            partial_sig: partial_sig.serialize().to_vec(),
        }))
    }
}
