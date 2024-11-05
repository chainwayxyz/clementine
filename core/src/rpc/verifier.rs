use std::sync::Arc;

use super::clementine::{
    self, clementine_verifier_server::ClementineVerifier, nonce_gen_response, Empty,
    NonceGenResponse, OperatorParams, PartialSig, VerifierDepositFinalizeParams,
    VerifierDepositSignParams, VerifierParams, VerifierPublicKeys, WatchtowerParams,
};
use crate::{
    actor::Actor,
    builder,
    musig2::{self, MuSigPubNonce, MuSigSecNonce},
    sha256_hash, utils,
    verifier::{NofN, NonceSession, Verifier},
    ByteArray32, ByteArray66, EVMAddress,
};
use bitcoin::{hashes::Hash, Amount, TapSighash};
use bitcoin_mock_rpc::RpcApiWrapper;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{async_trait, Request, Response, Status, Streaming};

pub const NUM_REQUIRED_SIGS: usize = 10;

#[async_trait]
impl<T> ClementineVerifier for Verifier<T>
where
    T: RpcApiWrapper,
{
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
            num_watchtowers: self.config.num_verifiers as u32, // TODO: Add num_watchtowers to config
            num_operators: self.config.num_operators as u32,
            num_time_txs: 10, // TODO: Add num_time_txs to config
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
        let verifiers_public_keys: Vec<secp256k1::PublicKey> = req
            .into_inner()
            .verifier_public_keys
            .iter()
            .map(|pk| secp256k1::PublicKey::from_slice(pk).unwrap())
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

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    #[allow(clippy::blocks_in_conditions)]
    async fn set_operator(
        &self,
        _request: Request<OperatorParams>,
    ) -> Result<Response<Empty>, Status> {
        todo!()
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    #[allow(clippy::blocks_in_conditions)]
    async fn set_watchtower(
        &self,
        _request: Request<WatchtowerParams>,
    ) -> Result<Response<Empty>, Status> {
        todo!()
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    #[allow(clippy::blocks_in_conditions)]
    async fn nonce_gen(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<Self::NonceGenStream>, Status> {
        let (sec_nonces, pub_nonces): (Vec<MuSigSecNonce>, Vec<MuSigPubNonce>) = (0
            ..NUM_REQUIRED_SIGS)
            .map(|_| {
                // nonce pair needs keypair and a rng
                let (sec_nonce, pub_nonce) =
                    musig2::nonce_pair(&self.signer.keypair, &mut secp256k1::rand::thread_rng());
                (sec_nonce, pub_nonce)
            })
            .unzip();

        let private_key = secp256k1::SecretKey::new(&mut secp256k1::rand::thread_rng());

        let session = NonceSession {
            private_key,
            nonces: sec_nonces,
        };

        // save the session
        let session_id = {
            let all_sessions = &mut *self.nonces.lock().await;
            let session_id = all_sessions.cur_id;
            all_sessions.sessions.insert(session_id, session);
            all_sessions.cur_id += 1;
            session_id
        };

        let public_key = secp256k1::PublicKey::from_secret_key(&utils::SECP, &private_key)
            .serialize()
            .to_vec();
        let public_key_hash = sha256_hash!(&public_key);

        let nonce_gen_first_response = clementine::NonceGenFirstResponse {
            id: session_id,
            public_key,
            sig: self
                .signer
                .sign(TapSighash::from_byte_array(public_key_hash))
                .serialize()
                .to_vec(),
            num_nonces: NUM_REQUIRED_SIGS as u32,
        };

        // now stream the nonces
        let (tx, rx) = mpsc::channel(128);
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
                    response: Some(nonce_gen_response::Response::PubNonce(pub_nonce.0.to_vec())),
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

        let (tx, rx) = mpsc::channel(128);

        tracing::info!("Received deposit sign request");

        let verifier_idx = self.idx;
        let nofn_xonly_pk = self.nofn_xonly_pk;
        let sessions = Arc::clone(&self.nonces);
        let signer = self.signer.clone();
        let verifiers_public_keys = self.config.verifiers_public_keys.clone();

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
                    deposit_sign_first_param,
                ) => {
                    let deposit_params = deposit_sign_first_param
                        .deposit_params
                        .ok_or(Status::internal("No deposit outpoint received"))
                        .unwrap();
                    let deposit_outpoint: bitcoin::OutPoint = deposit_params
                        .deposit_outpoint
                        .ok_or(Status::internal("No deposit outpoint received"))
                        .unwrap()
                        .try_into()
                        .unwrap();
                    let evm_address: EVMAddress = deposit_params.evm_address.try_into().unwrap();
                    let recovery_taproot_address = deposit_params
                        .recovery_taproot_address
                        .parse::<bitcoin::Address<_>>()
                        .unwrap();
                    let user_takes_after = deposit_params.user_takes_after;

                    let session_id =
                        deposit_sign_first_param.nonce_gen_first_responses[verifier_idx].id;
                    (
                        deposit_outpoint,
                        evm_address,
                        recovery_taproot_address,
                        user_takes_after,
                        session_id,
                    )
                }
                _ => panic!("Expected DepositOutpoint"),
            };

            let binding = sessions.lock().await;
            let session = binding
                .sessions
                .get(&session_id)
                .ok_or(Status::internal("No session found"))
                .unwrap();
            let mut nonce_idx: usize = 0;

            while let Some(result) = in_stream.message().await.unwrap() {
                let agg_nonce = match result
                    .params
                    .ok_or(Status::internal("No agg nonce received"))
                    .unwrap()
                {
                    clementine::verifier_deposit_sign_params::Params::AggNonce(agg_nonce) => {
                        ByteArray66(agg_nonce.try_into().unwrap())
                    }
                    _ => panic!("Expected AggNonce"),
                };

                let mut dummy_move_tx_handler = builder::transaction::create_move_tx_handler(
                    deposit_outpoint,
                    evm_address,
                    &recovery_taproot_address,
                    nofn_xonly_pk,
                    bitcoin::Network::Regtest,
                    user_takes_after as u32,
                    Amount::from_sat(nonce_idx as u64 + 1000000),
                );

                let move_tx_sighash = ByteArray32(
                    Actor::convert_tx_to_sighash_script_spend(&mut dummy_move_tx_handler, 0, 0)
                        .unwrap()
                        .to_byte_array(),
                );
                tracing::debug!(
                    "Verifier {} found sighash: {:?}",
                    verifier_idx,
                    move_tx_sighash
                );

                let move_tx_sig = musig2::partial_sign(
                    verifiers_public_keys.clone(),
                    None,
                    false,
                    session.nonces[nonce_idx],
                    agg_nonce,
                    &signer.keypair,
                    move_tx_sighash,
                );

                let partial_sig = PartialSig {
                    partial_sig: move_tx_sig.0.to_vec(),
                };

                tx.send(Ok(partial_sig)).await.unwrap();

                nonce_idx += 1;
                if nonce_idx == NUM_REQUIRED_SIGS {
                    break;
                }
            }
            // drop nonces
            let mut binding = sessions.lock().await;
            binding.sessions.remove(&session_id);
        });

        let out_stream: Self::DepositSignStream = ReceiverStream::new(rx);
        Ok(Response::new(out_stream))
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    #[allow(clippy::blocks_in_conditions)]
    async fn deposit_finalize(
        &self,
        req: Request<Streaming<VerifierDepositFinalizeParams>>,
    ) -> Result<Response<PartialSig>, Status> {
        let verifier_idx = self.idx;
        let nofn_xonly_pk = self.nofn_xonly_pk;

        let mut in_stream = req.into_inner();

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
            _session_id,
        ) = match params {
            clementine::verifier_deposit_finalize_params::Params::DepositSignFirstParam(
                deposit_sign_first_param,
            ) => {
                let deposit_params = deposit_sign_first_param
                    .deposit_params
                    .ok_or(Status::internal("No deposit outpoint received"))
                    .unwrap();
                let deposit_outpoint: bitcoin::OutPoint = deposit_params
                    .deposit_outpoint
                    .ok_or(Status::internal("No deposit outpoint received"))
                    .unwrap()
                    .try_into()
                    .unwrap();
                let evm_address: EVMAddress = deposit_params.evm_address.try_into().unwrap();
                let recovery_taproot_address = deposit_params
                    .recovery_taproot_address
                    .parse::<bitcoin::Address<_>>()
                    .unwrap();
                let user_takes_after = deposit_params.user_takes_after;

                let session_id =
                    deposit_sign_first_param.nonce_gen_first_responses[verifier_idx].id;
                (
                    deposit_outpoint,
                    evm_address,
                    recovery_taproot_address,
                    user_takes_after,
                    session_id,
                )
            }
            _ => panic!("Expected DepositOutpoint"),
        };

        let mut nonce_idx: usize = 0;
        while let Some(result) = in_stream.message().await.unwrap() {
            let mut dummy_move_tx_handler = builder::transaction::create_move_tx_handler(
                deposit_outpoint,
                evm_address,
                &recovery_taproot_address,
                nofn_xonly_pk,
                bitcoin::Network::Regtest,
                user_takes_after as u32,
                Amount::from_sat(nonce_idx as u64 + 1000000),
            );

            let move_tx_sighash = ByteArray32(
                Actor::convert_tx_to_sighash_script_spend(&mut dummy_move_tx_handler, 0, 0)
                    .unwrap()
                    .to_byte_array(),
            );

            let final_sig = result
                .params
                .ok_or(Status::internal("No final sig received"))
                .unwrap();
            let final_sig = match final_sig {
                clementine::verifier_deposit_finalize_params::Params::SchnorrSig(final_sig) => {
                    secp256k1::schnorr::Signature::from_slice(&final_sig).unwrap()
                }
                _ => panic!("Expected FinalSig"),
            };

            tracing::debug!("Verifying Final Signature");
            utils::SECP
                .verify_schnorr(
                    &final_sig,
                    &secp256k1::Message::from_digest(move_tx_sighash.0),
                    &nofn_xonly_pk,
                )
                .unwrap();

            tracing::debug!("Final Signature Verified");

            nonce_idx += 1;
            if nonce_idx == NUM_REQUIRED_SIGS {
                break;
            }
        }

        tracing::info!("Deposit finalized");

        Ok(Response::new(PartialSig {
            partial_sig: vec![1, 2],
        }))
    }
}
