use super::clementine::{
    self, clementine_verifier_server::ClementineVerifier, nonce_gen_response, Empty,
    NonceGenResponse, OperatorParams, PartialSig, VerifierDepositFinalizeParams,
    VerifierDepositSignParams, VerifierParams, VerifierPublicKeys, WatchtowerParams,
};
use crate::{
    musig2::{self, MuSigPubNonce, MuSigSecNonce},
    sha256_hash, utils,
    verifier::{NonceSession, Verifier},
};
use bitcoin::{hashes::Hash, TapSighash};
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

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn deposit_sign(
        &self,
        req: Request<Streaming<VerifierDepositSignParams>>,
    ) -> Result<Response<Self::DepositSignStream>, Status> {
        let mut in_stream = req.into_inner();
        let (tx, rx) = mpsc::channel(128);

        let first_message = in_stream
            .message()
            .await
            .unwrap()
            .ok_or(Status::internal("No first message received"))
            .unwrap();

        println!("\tfirst message: {:?}", first_message);

        tokio::spawn(async move {
            while let Some(result) = in_stream.message().await.unwrap() {
                let agg_nonce = match result
                    .params
                    .ok_or(Status::internal("No agg nonce received"))
                    .unwrap()
                {
                    clementine::verifier_deposit_sign_params::Params::AggNonce(agg_nonce) => {
                        agg_nonce
                    }
                    _ => panic!("Expected AggNonce"),
                };

                let partial_sig = PartialSig {
                    partial_sig: agg_nonce.iter().rev().cloned().collect(),
                };

                tx.send(Ok(partial_sig)).await.unwrap();
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
