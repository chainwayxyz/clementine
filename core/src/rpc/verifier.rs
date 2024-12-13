use super::clementine::{
    self, clementine_verifier_server::ClementineVerifier, nonce_gen_response, Empty,
    NonceGenRequest, NonceGenResponse, OperatorParams, PartialSig, VerifierDepositFinalizeParams,
    VerifierDepositSignParams, VerifierParams, VerifierPublicKeys, WatchtowerParams,
};
use crate::{
    builder::{self, sighash::create_nofn_sighash_stream},
    errors::BridgeError,
    musig2::{self, MuSigPubNonce, MuSigSecNonce},
    sha256_hash, utils,
    verifier::{NofN, NonceSession, Verifier},
    ByteArray32, ByteArray66, EVMAddress,
};
use bitcoin::{hashes::Hash, Amount, TapSighash, Txid};
use bitvm::{
    bridge::transactions::signing_winternitz::WinternitzPublicKey, signatures::winternitz,
};
use futures::StreamExt;
use secp256k1::{schnorr, Message};
use std::{pin::pin, str::FromStr};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{async_trait, Request, Response, Status, Streaming};

pub const NUM_REQUIRED_SIGS: usize = 10;

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
    async fn set_operator(&self, req: Request<OperatorParams>) -> Result<Response<Empty>, Status> {
        let operator_params = req.into_inner();

        let operator_config = operator_params
            .operator_details
            .ok_or(BridgeError::Error("No operator details".to_string()))?;

        let operator_xonly_pk = secp256k1::XOnlyPublicKey::from_str(&operator_config.xonly_pk)
            .map_err(|_| BridgeError::Error("Invalid xonly public key".to_string()))?;

        // Save the operator details to the db
        self.db
            .set_operator(
                None,
                operator_config.operator_idx as i32,
                operator_xonly_pk,
                operator_config.wallet_reimburse_address,
            )
            .await?;

        let timeout_tx_sigs: Vec<schnorr::Signature> = operator_params
            .timeout_tx_sigs
            .iter()
            .map(|sig| secp256k1::schnorr::Signature::from_slice(sig).unwrap())
            .collect();

        let timeout_tx_sighash_stream = builder::sighash::create_timout_tx_sighash_stream(
            operator_xonly_pk,
            Txid::from_slice(&operator_config.collateral_funding_txid).unwrap(),
            Amount::from_sat(200_000_000), // TODO: Fix this.
            3024,
            6,
            100,
            self.config.network,
        );

        // Verify the signatures
        let results: Vec<Result<(), _>> = timeout_tx_sighash_stream
            .enumerate()
            .map(|(i, sighash)| {
                utils::SECP.verify_schnorr(
                    &timeout_tx_sigs[i],
                    &Message::from(sighash),
                    &operator_xonly_pk,
                )
            })
            .collect()
            .await;

        // Check if all verifications succeeded
        let x = results.iter().all(|res| res.is_ok());
        if !x {
            return Err(Status::internal(
                "Failed to verify all timeout tx signatures",
            ));
        }

        self.db
            .save_timeout_tx_sigs(None, operator_config.operator_idx, timeout_tx_sigs)
            .await?;

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
        let winternitz_public_keys = watchtower_params
            .winternitz_pubkeys
            .into_iter()
            .map(|wpk| {
                Ok(WinternitzPublicKey {
                    public_key: wpk.to_bitvm(),
                    parameters: winternitz::Parameters::new(0, 4),
                })
            })
            .collect::<Result<Vec<_>, BridgeError>>()?;

        let required_number_of_pubkeys = self.config.num_operators * self.config.num_time_txs;
        if winternitz_public_keys.len() != required_number_of_pubkeys {
            return Err(Status::invalid_argument(format!(
                "Request has {} Winternitz public keys but it needs to be {}!",
                winternitz_public_keys.len(),
                required_number_of_pubkeys
            )));
        }

        for operator_idx in 0..self.config.num_operators {
            let index = operator_idx * self.config.num_time_txs;
            self.db
                .save_winternitz_public_key(
                    None,
                    watchtower_params.watchtower_id,
                    operator_idx as u32,
                    winternitz_public_keys[index..index + self.config.num_time_txs].to_vec(),
                )
                .await?;
        }

        Ok(Response::new(Empty {}))
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    #[allow(clippy::blocks_in_conditions)]
    async fn nonce_gen(
        &self,
        req: Request<NonceGenRequest>,
    ) -> Result<Response<Self::NonceGenStream>, Status> {
        let num_nonces = req.into_inner().num_nonces as usize;
        let (sec_nonces, pub_nonces): (Vec<MuSigSecNonce>, Vec<MuSigPubNonce>) = (0..num_nonces)
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
            num_nonces: num_nonces as u32,
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
                        deposit_sign_first_param.nonce_gen_first_responses[verifier.idx].id;
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

            let binding = verifier.nonces.lock().await;
            let session = binding
                .sessions
                .get(&session_id)
                .ok_or(Status::internal("No session found"))
                .unwrap();
            let mut nonce_idx: usize = 0;

            let mut sighash_stream = pin!(create_nofn_sighash_stream(
                verifier.db,
                deposit_outpoint,
                evm_address,
                recovery_taproot_address,
                user_takes_after,
                verifier.nofn_xonly_pk,
            ));

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

                let sighash = sighash_stream.next().await.unwrap();
                tracing::debug!("Verifier {} found sighash: {:?}", verifier.idx, sighash);

                let move_tx_sig = musig2::partial_sign(
                    verifier.config.verifiers_public_keys.clone(),
                    None,
                    false,
                    session.nonces[nonce_idx],
                    agg_nonce,
                    &verifier.signer.keypair,
                    ByteArray32(sighash.to_byte_array()),
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
            let mut binding = verifier.nonces.lock().await;
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
        let mut in_stream = req.into_inner();

        let first_message = in_stream
            .message()
            .await?
            .ok_or(Status::internal("No first message received"))?;

        // Parse the first message
        let params = first_message
            .params
            .ok_or(Status::internal("No deposit outpoint received"))?;
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
                    .ok_or(Status::internal("No deposit outpoint received"))?;
                let deposit_outpoint: bitcoin::OutPoint = deposit_params
                    .deposit_outpoint
                    .ok_or(Status::internal("No deposit outpoint received"))?
                    .try_into()?;
                let evm_address: EVMAddress = deposit_params.evm_address.try_into().unwrap();
                let recovery_taproot_address = deposit_params
                    .recovery_taproot_address
                    .parse::<bitcoin::Address<_>>()
                    .map_err(|e| BridgeError::Error(e.to_string()))?;
                let user_takes_after = deposit_params.user_takes_after;

                let session_id = deposit_sign_first_param.nonce_gen_first_responses[self.idx].id;
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

        let mut sighash_stream = pin!(create_nofn_sighash_stream(
            self.db.clone(),
            deposit_outpoint,
            evm_address,
            recovery_taproot_address,
            user_takes_after,
            self.nofn_xonly_pk,
        ));

        let mut nonce_idx: usize = 0;
        while let Some(result) = in_stream.message().await.unwrap() {
            let sighash = sighash_stream.next().await.unwrap();
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
                    &secp256k1::Message::from(sighash),
                    &self.nofn_xonly_pk,
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
