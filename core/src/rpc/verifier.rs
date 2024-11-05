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
    verifier::{NonceSession, Verifier},
    ByteArray32, ByteArray66, EVMAddress,
};
use bitcoin::{hashes::Hash, Amount, TapSighash};
use bitcoin_mock_rpc::RpcApiWrapper;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{async_trait, Request, Response, Status, Streaming};

#[async_trait]
impl<T> ClementineVerifier for Verifier<T>
where
    T: RpcApiWrapper,
{
    type NonceGenStream = ReceiverStream<Result<NonceGenResponse, Status>>;
    type DepositSignStream = ReceiverStream<Result<PartialSig, Status>>;

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn get_params(&self, _: Request<Empty>) -> Result<Response<VerifierParams>, Status> {
        todo!()
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn set_verifiers(
        &self,
        _request: Request<VerifierPublicKeys>,
    ) -> Result<Response<Empty>, Status> {
        todo!()
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn set_operator(
        &self,
        _request: Request<OperatorParams>,
    ) -> Result<Response<Empty>, Status> {
        todo!()
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn set_watchtower(
        &self,
        _request: Request<WatchtowerParams>,
    ) -> Result<Response<Empty>, Status> {
        todo!()
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn nonce_gen(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<Self::NonceGenStream>, Status> {
        let num_required_nonces = 10;

        let (sec_nonces, pub_nonces): (Vec<MuSigSecNonce>, Vec<MuSigPubNonce>) = (0
            ..num_required_nonces)
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
            all_sessions.cur_id = all_sessions.cur_id + 1;
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
            num_nonces: num_required_nonces as u32,
        };

        // now stream the nonces
        let buffer_size = 4;
        let (tx, rx) = mpsc::channel(buffer_size);
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
        let nofn_xonly_pk = self.nofn_xonly_pk.clone();
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

                let move_tx_sig = musig2::partial_sign(
                    verifiers_public_keys.clone(),
                    None,
                    false,
                    session.nonces[nonce_idx].clone(),
                    agg_nonce,
                    &signer.keypair,
                    move_tx_sighash,
                );

                let partial_sig = PartialSig {
                    partial_sig: move_tx_sig.0.to_vec(),
                };

                tx.send(Ok(partial_sig)).await.unwrap();

                nonce_idx += 1;
            }
            println!("\tstream ended");
        });

        let out_stream: Self::DepositSignStream = ReceiverStream::new(rx);
        Ok(Response::new(out_stream))
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn deposit_finalize(
        &self,
        _request: Request<Streaming<VerifierDepositFinalizeParams>>,
    ) -> Result<Response<PartialSig>, Status> {
        todo!()
    }
}
