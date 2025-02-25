use crate::actor::Actor;
use crate::builder::address::{
    derive_challenge_address_from_xonlypk_and_wpk, taproot_builder_with_scripts,
};
use crate::builder::script::{SpendableScript, WinternitzCommit};
use crate::builder::sighash::{
    create_nofn_sighash_stream, create_operator_sighash_stream, PartialSignatureInfo, SignatureInfo,
};
use crate::builder::transaction::deposit_signature_owner::EntityType;
use crate::builder::transaction::{
    create_move_to_vault_txhandler, DepositData, OperatorData, TransactionType, TxHandler, Unsigned,
};
use crate::builder::transaction::{create_round_txhandlers, KickoffWinternitzKeys};
use crate::builder::{self};
use crate::config::BridgeConfig;
use crate::constants::WATCHTOWER_CHALLENGE_MESSAGE_LENGTH;
use crate::database::Database;
use crate::errors::BridgeError;
use crate::extended_rpc::ExtendedRpc;
use crate::musig2::{self, AggregateFromPublicKeys};
use crate::rpc::clementine::{OperatorKeys, TaggedSignature, WatchtowerKeys};
use crate::tx_sender::TxSender;
use crate::utils::{self, SECP};
use crate::{bitcoin_syncer, EVMAddress, UTXO};
use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::Message;
use bitcoin::{secp256k1::PublicKey, OutPoint};
use bitcoin::{Address, ScriptBuf, TapTweakHash, XOnlyPublicKey};
use bitvm::signatures::winternitz;
use secp256k1::musig::{MusigAggNonce, MusigPartialSignature, MusigPubNonce, MusigSecNonce};
use std::collections::HashMap;
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;

#[derive(Debug)]
pub struct NonceSession {
    /// Nonces used for a deposit session (last nonce is for the movetx signature)
    pub nonces: Vec<MusigSecNonce>,
}

#[derive(Debug)]
pub struct AllSessions {
    pub cur_id: u32,
    pub sessions: HashMap<u32, NonceSession>,
}

#[derive(Debug, Clone)]
pub struct NofN {
    pub public_keys: Vec<bitcoin::secp256k1::PublicKey>,
    pub agg_xonly_pk: bitcoin::secp256k1::XOnlyPublicKey,
    pub idx: usize,
}

impl NofN {
    pub fn new(
        self_pk: bitcoin::secp256k1::PublicKey,
        public_keys: Vec<bitcoin::secp256k1::PublicKey>,
    ) -> Result<Self, BridgeError> {
        let idx = public_keys
            .iter()
            .position(|pk| pk == &self_pk)
            .ok_or(BridgeError::PublicKeyNotFound)?;
        let agg_xonly_pk =
            bitcoin::secp256k1::XOnlyPublicKey::from_musig2_pks(public_keys.clone(), None)?;
        Ok(NofN {
            public_keys,
            agg_xonly_pk,
            idx,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Verifier {
    _rpc: ExtendedRpc,
    pub(crate) signer: Actor,
    pub(crate) db: Database,
    pub(crate) config: BridgeConfig,
    pub(crate) nofn_xonly_pk: bitcoin::secp256k1::XOnlyPublicKey,
    pub(crate) nofn: Arc<tokio::sync::RwLock<Option<NofN>>>,
    _operator_xonly_pks: Vec<bitcoin::secp256k1::XOnlyPublicKey>,
    pub(crate) nonces: Arc<tokio::sync::Mutex<AllSessions>>,
    pub idx: usize,
    pub tx_sender: TxSender,
}

impl Verifier {
    pub async fn new(config: BridgeConfig) -> Result<Self, BridgeError> {
        let signer = Actor::new(
            config.secret_key,
            config.winternitz_secret_key,
            config.network,
        );

        // let pk: bitcoin::secp256k1:: PublicKey = config.secret_key.public_key(&utils::SECP);

        // TODO: In the future, we won't get verifiers public keys from config files, rather in set_verifiers rpc call.
        let idx = config
            .verifiers_public_keys
            .iter()
            .position(|pk| pk == &signer.public_key)
            .ok_or(BridgeError::PublicKeyNotFound)?;

        let db = Database::new(&config).await?;
        let rpc = ExtendedRpc::connect(
            config.bitcoin_rpc_url.clone(),
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
        )
        .await?;

        let tx_sender = TxSender::new(
            signer.clone(),
            rpc.clone(),
            db.clone(),
            &format!("verifier_{}", idx).to_string(),
            config.network,
        );
        let _tx_sender_handle = tx_sender.run(Duration::from_secs(1)).await?;

        let nofn_xonly_pk = bitcoin::secp256k1::XOnlyPublicKey::from_musig2_pks(
            config.verifiers_public_keys.clone(),
            None,
        )?;

        let operator_xonly_pks = config.operators_xonly_pks.clone();

        let all_sessions = AllSessions {
            cur_id: 0,
            sessions: HashMap::new(),
        };

        let verifiers_pks = db.get_verifiers_public_keys(None).await?;

        let nofn = if !verifiers_pks.is_empty() {
            tracing::debug!("Verifiers public keys found: {:?}", verifiers_pks);
            let nofn = NofN::new(signer.public_key, verifiers_pks)?;
            Some(nofn)
        } else {
            None
        };

        bitcoin_syncer::set_initial_block_info_if_not_exists(&db, &rpc).await?;
        let _handle =
            bitcoin_syncer::start_bitcoin_syncer(db.clone(), rpc.clone(), Duration::from_secs(1))
                .await?;

        Ok(Verifier {
            _rpc: rpc,
            signer,
            db,
            config,
            nofn_xonly_pk,
            nofn: Arc::new(tokio::sync::RwLock::new(nofn)),
            _operator_xonly_pks: operator_xonly_pks,
            nonces: Arc::new(tokio::sync::Mutex::new(all_sessions)),
            idx,
            tx_sender,
        })
    }

    pub async fn set_verifiers(
        &self,
        verifiers_public_keys: Vec<PublicKey>,
    ) -> Result<(), BridgeError> {
        // Check if verifiers are already set
        if self.nofn.read().await.clone().is_some() {
            return Err(BridgeError::AlreadyInitialized);
        }

        // Save verifiers public keys to db
        self.db
            .set_verifiers_public_keys(None, &verifiers_public_keys)
            .await?;

        // Save the nofn to memory for fast access
        let nofn = NofN::new(self.signer.public_key, verifiers_public_keys.clone())?;
        self.nofn.write().await.replace(nofn);

        Ok(())
    }

    /// Verifies all unspent kickoff signatures sent by the operator, converts them to TaggedSignature
    /// as they will be saved as TaggedSignatures to the db.
    fn verify_unspent_kickoff_sigs(
        &self,
        operator_index: u32,
        collateral_funding_outpoint: OutPoint,
        operator_xonly_pk: XOnlyPublicKey,
        wallet_reimburse_address: Address,
        unspent_kickoff_sigs: Vec<Signature>,
        kickoff_wpks: &KickoffWinternitzKeys,
    ) -> Result<Vec<TaggedSignature>, BridgeError> {
        let mut tagged_sigs = Vec::with_capacity(unspent_kickoff_sigs.len());
        let mut prev_ready_to_reimburse: Option<TxHandler> = None;
        let operator_data = OperatorData {
            xonly_pk: operator_xonly_pk,
            collateral_funding_outpoint,
            reimburse_addr: wallet_reimburse_address.clone(),
        };
        let mut cur_sig_index = 0;
        for idx in 0..self.config.num_round_txs {
            let txhandlers = create_round_txhandlers(
                &self.config,
                idx,
                &operator_data,
                kickoff_wpks,
                prev_ready_to_reimburse.clone(),
            )?;
            for txhandler in txhandlers {
                if let TransactionType::UnspentKickoff(kickoff_idx) =
                    txhandler.get_transaction_type()
                {
                    let partial = PartialSignatureInfo {
                        operator_idx: operator_index as usize,
                        round_idx: idx,
                        kickoff_utxo_idx: kickoff_idx,
                    };
                    let sighashes = txhandler
                        .calculate_shared_txins_sighash(EntityType::OperatorSetup, partial)?;
                    for sighash in sighashes {
                        let message = Message::from_digest(sighash.0.to_byte_array());
                        utils::SECP
                            .verify_schnorr(
                                &unspent_kickoff_sigs[cur_sig_index],
                                &message,
                                &operator_xonly_pk,
                            )
                            .map_err(|e| {
                                BridgeError::Error(format!(
                                    "Unspent kickoff signature verification failed for num sig {}: {}",
                                    cur_sig_index + 1,
                                    e
                                ))
                            })?;
                        tagged_sigs.push(TaggedSignature {
                            signature: unspent_kickoff_sigs[cur_sig_index].serialize().to_vec(),
                            signature_id: Some(sighash.1.signature_id),
                        });
                        cur_sig_index += 1;
                    }
                }
                if let TransactionType::ReadyToReimburse = txhandler.get_transaction_type() {
                    prev_ready_to_reimburse = Some(txhandler);
                }
            }
        }

        Ok(tagged_sigs)
    }

    pub async fn set_operator(
        &self,
        operator_index: u32,
        collateral_funding_outpoint: OutPoint,
        operator_xonly_pk: XOnlyPublicKey,
        wallet_reimburse_address: Address,
        operator_winternitz_public_keys: Vec<winternitz::PublicKey>,
        unspent_kickoff_sigs: Vec<Signature>,
    ) -> Result<(), BridgeError> {
        let kickoff_wpks = KickoffWinternitzKeys::new(
            operator_winternitz_public_keys,
            self.config.num_kickoffs_per_round,
        );
        let tagged_sigs = self.verify_unspent_kickoff_sigs(
            operator_index,
            collateral_funding_outpoint,
            operator_xonly_pk,
            wallet_reimburse_address.clone(),
            unspent_kickoff_sigs,
            &kickoff_wpks,
        )?;

        let operator_winternitz_public_keys = kickoff_wpks.keys;
        // Save the operator details to the db
        self.db
            .set_operator(
                None,
                operator_index as i32,
                operator_xonly_pk,
                wallet_reimburse_address.to_string(),
                collateral_funding_outpoint,
            )
            .await?;

        self.db
            .set_operator_kickoff_winternitz_public_keys(
                None,
                operator_index,
                operator_winternitz_public_keys,
            )
            .await?;

        let sigs_per_round = self.config.get_num_unspent_kickoff_sigs() / self.config.num_round_txs;
        let tagged_sigs_per_round: Vec<Vec<TaggedSignature>> = tagged_sigs
            .chunks(sigs_per_round)
            .map(|chunk| chunk.to_vec())
            .collect();

        for (round_idx, sigs) in tagged_sigs_per_round.into_iter().enumerate() {
            self.db
                .set_unspent_kickoff_sigs(None, operator_index as usize, round_idx, sigs)
                .await?;
        }

        Ok(())
    }

    #[tracing::instrument(skip(self, xonly_pk), fields(verifier_idx = self.idx), ret)]
    pub async fn set_watchtower(
        &self,
        watchtower_idx: u32,
        xonly_pk: XOnlyPublicKey,
    ) -> Result<(), BridgeError> {
        self.db
            .set_watchtower_xonly_pk(None, watchtower_idx, &xonly_pk)
            .await?;

        Ok(())
    }

    pub async fn nonce_gen(
        &self,
        num_nonces: u32,
    ) -> Result<(u32, Vec<MusigPubNonce>), BridgeError> {
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

        Ok((session_id, pub_nonces))
    }

    pub async fn deposit_sign(
        &self,
        deposit_outpoint: OutPoint,
        evm_address: EVMAddress,
        recovery_taproot_address: Address<NetworkUnchecked>,
        session_id: u32,
        mut agg_nonce_rx: mpsc::Receiver<MusigAggNonce>,
    ) -> Result<mpsc::Receiver<MusigPartialSignature>, BridgeError> {
        let verifier = self.clone();
        let (partial_sig_tx, partial_sig_rx) = mpsc::channel(1280);

        tokio::spawn(async move {
            let mut session_map = verifier.nonces.lock().await;
            let session = session_map.sessions.get_mut(&session_id).ok_or_else(|| {
                BridgeError::Error(format!("Could not find session id {session_id}"))
            })?;
            session.nonces.reverse();

            let mut nonce_idx: usize = 0;

            let mut sighash_stream = Box::pin(create_nofn_sighash_stream(
                verifier.db.clone(),
                verifier.config.clone(),
                DepositData {
                    deposit_outpoint,
                    evm_address,
                    recovery_taproot_address,
                },
                verifier.nofn_xonly_pk,
            ));
            let num_required_sigs = verifier.config.get_num_required_nofn_sigs();

            assert_eq!(
                num_required_sigs + 1,
                session.nonces.len(),
                "Expected nonce count to be num_required_sigs + 1 (movetx)"
            );

            while let Some(agg_nonce) = agg_nonce_rx.recv().await {
                let sighash = sighash_stream
                    .next()
                    .await
                    .ok_or(BridgeError::Error("No sighash received".to_string()))??;
                tracing::debug!("Verifier {} found sighash: {:?}", verifier.idx, sighash);

                let nonce = session
                    .nonces
                    .pop()
                    .ok_or(BridgeError::Error("No nonce available".to_string()))?;
                let partial_sig = musig2::partial_sign(
                    verifier.config.verifiers_public_keys.clone(),
                    None,
                    nonce,
                    agg_nonce,
                    verifier.signer.keypair,
                    Message::from_digest(*sighash.0.as_byte_array()),
                )?;
                partial_sig_tx
                    .send(partial_sig)
                    .await
                    .map_err(|e| BridgeError::SendError("partial signature", e.to_string()))?;

                nonce_idx += 1;
                tracing::debug!(
                    "Verifier {} signed and sent sighash {} of {}",
                    verifier.idx,
                    nonce_idx,
                    num_required_sigs
                );
                if nonce_idx == num_required_sigs {
                    break;
                }
            }

            let last_nonce = session
                .nonces
                .pop()
                .ok_or(BridgeError::Error("No last nonce available".to_string()))?;
            session.nonces.clear();
            session.nonces.push(last_nonce);

            Ok::<(), BridgeError>(())
        });

        Ok(partial_sig_rx)
    }

    pub async fn deposit_finalize(
        &self,
        deposit_outpoint: OutPoint,
        evm_address: EVMAddress,
        recovery_taproot_address: Address<NetworkUnchecked>,
        session_id: u32,
        mut sig_receiver: mpsc::Receiver<Signature>,
        mut agg_nonce_receiver: mpsc::Receiver<MusigAggNonce>,
        mut operator_sig_receiver: mpsc::Receiver<Signature>,
    ) -> Result<MusigPartialSignature, BridgeError> {
        let mut sighash_stream = pin!(create_nofn_sighash_stream(
            self.db.clone(),
            self.config.clone(),
            DepositData {
                deposit_outpoint,
                evm_address,
                recovery_taproot_address: recovery_taproot_address.clone(),
            },
            self.nofn_xonly_pk,
        ));

        let num_required_nofn_sigs = self.config.get_num_required_nofn_sigs();
        let num_required_nofn_sigs_per_kickoff =
            self.config.get_num_required_nofn_sigs_per_kickoff();
        let num_required_op_sigs = self.config.get_num_required_operator_sigs();
        let num_required_op_sigs_per_kickoff =
            self.config.get_num_required_operator_sigs_per_kickoff();
        let &BridgeConfig {
            num_operators,
            num_round_txs,
            num_kickoffs_per_round,
            ..
        } = &self.config;
        let mut verified_sigs = vec![
            vec![
                vec![
                    Vec::<TaggedSignature>::with_capacity(
                        num_required_nofn_sigs_per_kickoff + num_required_op_sigs_per_kickoff
                    );
                    num_kickoffs_per_round
                ];
                num_round_txs
            ];
            num_operators
        ];

        let mut nonce_idx: usize = 0;

        while let Some(sig) = sig_receiver.recv().await {
            let sighash = sighash_stream
                .next()
                .await
                .ok_or(BridgeError::SighashStreamEndedPrematurely)??;

            tracing::debug!("Verifying Final nofn Signature {}", nonce_idx + 1);
            utils::SECP
                .verify_schnorr(&sig, &Message::from(sighash.0), &self.nofn_xonly_pk)
                .map_err(|x| {
                    BridgeError::Error(format!(
                        "Nofn Signature {} Verification Failed: {}.",
                        nonce_idx + 1,
                        x
                    ))
                })?;
            let &SignatureInfo {
                operator_idx,
                round_idx,
                kickoff_utxo_idx,
                signature_id,
            } = &sighash.1;
            let tagged_sig = TaggedSignature {
                signature: sig.serialize().to_vec(),
                signature_id: Some(signature_id),
            };
            verified_sigs[operator_idx][round_idx][kickoff_utxo_idx].push(tagged_sig);
            tracing::debug!("Final Signature Verified");

            nonce_idx += 1;
            if nonce_idx == num_required_nofn_sigs {
                break;
            }
        }

        if nonce_idx != num_required_nofn_sigs {
            return Err(BridgeError::Error(format!(
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
            agg_nonce_receiver
                .recv()
                .await
                .ok_or(BridgeError::ChannelEndedPrematurely(
                    "verifier::deposit_finalize",
                    "aggregated nonces",
                ))?;

        let movetx_secnonce = {
            let mut session_map = self.nonces.lock().await;
            let session = session_map.sessions.get_mut(&session_id).ok_or_else(|| {
                BridgeError::Error(format!(
                    "could not find session with id {} in session cache",
                    session_id
                ))
            })?;
            session
                .nonces
                .pop()
                .ok_or_else(|| BridgeError::Error("No move tx secnonce in session".to_string()))?
        };

        let num_required_total_op_sigs = num_required_op_sigs * self.config.num_operators;
        let mut total_op_sig_count = 0;

        // get operator data
        let operators_data: Vec<(XOnlyPublicKey, bitcoin::Address, OutPoint)> =
            self.db.get_operators(None).await?;

        // get signatures of operators and verify them
        for (operator_idx, (op_xonly_pk, reimburse_addr, collateral_outpoint)) in
            operators_data.iter().enumerate()
        {
            let mut op_sig_count = 0;
            // tweak the operator xonly public key with None (because merkle root is empty as operator utxos have no scripts)
            let scalar = TapTweakHash::from_key_and_tweak(*op_xonly_pk, None).to_scalar();
            let tweaked_op_xonly_pk = op_xonly_pk
                .add_tweak(&SECP, &scalar)
                .map_err(|x| {
                    BridgeError::Error(format!("Failed to tweak operator xonly public key: {}", x))
                })?
                .0;
            // generate the sighash stream for operator
            let mut sighash_stream = pin!(create_operator_sighash_stream(
                self.db.clone(),
                operator_idx,
                *collateral_outpoint,
                reimburse_addr.clone(),
                *op_xonly_pk,
                self.config.clone(),
                DepositData {
                    deposit_outpoint,
                    evm_address,
                    recovery_taproot_address: recovery_taproot_address.clone(),
                },
                self.nofn_xonly_pk,
            ));
            while let Some(operator_sig) = operator_sig_receiver.recv().await {
                let sighash = sighash_stream
                    .next()
                    .await
                    .ok_or(BridgeError::SighashStreamEndedPrematurely)??;

                tracing::debug!(
                    "Verifying Final operator Signature {} for operator {}",
                    nonce_idx + 1,
                    operator_idx
                );

                utils::SECP
                    .verify_schnorr(
                        &operator_sig,
                        &Message::from(sighash.0),
                        &tweaked_op_xonly_pk,
                    )
                    .map_err(|x| {
                        BridgeError::Error(format!(
                            "Operator {} Signature {}: verification failed: {}.",
                            operator_idx,
                            op_sig_count + 1,
                            x
                        ))
                    })?;

                let &SignatureInfo {
                    operator_idx,
                    round_idx,
                    kickoff_utxo_idx,
                    signature_id,
                } = &sighash.1;
                let tagged_sig = TaggedSignature {
                    signature: operator_sig.serialize().to_vec(),
                    signature_id: Some(signature_id),
                };
                verified_sigs[operator_idx][round_idx][kickoff_utxo_idx].push(tagged_sig);

                op_sig_count += 1;
                total_op_sig_count += 1;
                if op_sig_count == num_required_op_sigs {
                    break;
                }
            }
        }

        if total_op_sig_count != num_required_total_op_sigs {
            return Err(BridgeError::Error(format!(
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

        Ok(partial_sig)
    }

    // / Inform verifiers about the new deposit request
    // /
    // / 1. Check if the deposit UTXO is valid, finalized (6 blocks confirmation) and not spent
    // / 2. Generate random pubNonces, secNonces
    // / 3. Save pubNonces and secNonces to a db
    // / 4. Return pubNonces
    // #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    // pub async fn new_deposit(
    //     &self,
    //     deposit_outpoint: OutPoint,
    //     recovery_taproot_address: Address<NetworkUnchecked>,
    //     evm_address: EVMAddress,
    // ) -> Result<Vec<MusigPubNonce>, BridgeError> {
    //     self.rpc
    //         .check_deposit_utxo(
    //             self.nofn_xonly_pk,
    //             &deposit_outpoint,
    //             &recovery_taproot_address,
    //             evm_address,
    //             self.config.bridge_amount_sats,
    //             self.config.confirmation_threshold,
    //             self.config.network,
    //             self.config.user_takes_after,
    //         )
    //         .await?;

    //     // For now we multiply by 2 since we do not give signatures for burn_txs. // TODO: Change this in future.
    //     let num_required_nonces = 2 * self.operator_xonly_pks.len() + 1;

    //     let mut dbtx = self.db.begin_transaction().await?;
    //     // Check if we already have pub_nonces for this deposit_outpoint.
    //     let pub_nonces_from_db = self
    //         .db
    //         .get_pub_nonces(Some(&mut dbtx), deposit_outpoint)
    //         .await?;
    //     if let Some(pub_nonces) = pub_nonces_from_db {
    //         if !pub_nonces.is_empty() {
    //             if pub_nonces.len() != num_required_nonces {
    //                 return Err(BridgeError::NoncesNotFound);
    //             }
    //             dbtx.commit().await?;
    //             return Ok(pub_nonces);
    //         }
    //     }

    //     let nonces = (0..num_required_nonces)
    //         .map(|_| musig2::nonce_pair(&self.signer.keypair, &mut rand::rngs::OsRng).1)
    //         .collect::<Vec<_>>();

    //     self.db
    //         .save_deposit_info(
    //             Some(&mut dbtx),
    //             deposit_outpoint,
    //             recovery_taproot_address,
    //             evm_address,
    //         )
    //         .await?;
    //     self.db
    //         .save_nonces(Some(&mut dbtx), deposit_outpoint, &nonces)
    //         .await?;
    //     dbtx.commit().await?;

    //     let pub_nonces = nonces.iter().map(|pub_nonce| *pub_nonce).collect();

    //     Ok(pub_nonces)
    // }

    /// - Verify operators signatures about kickoffs
    /// - Check the kickoff_utxos
    /// - Save agg_nonces to a db for future use
    /// - for every kickoff_utxo, calculate slash_or_take_tx
    /// - for every slash_or_take_tx, partial sign slash_or_take_tx
    /// - for every slash_or_take_tx, partial sign burn_tx (omitted for now)
    /// - return burn_txs partial signatures (omitted for now) TODO: For this bit,
    ///
    /// do not forget to add tweak when signing since this address has n_of_n as internal_key
    /// and operator_timelock as script.
    // #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    // pub async fn operator_kickoffs_generated(
    //     &self,
    //     deposit_outpoint: OutPoint,
    //     kickoff_utxos: Vec<UTXO>,
    //     operators_kickoff_sigs: Vec<bitcoin::secp256k1:: schnorr::Signature>, // These are not transaction signatures, rather, they are to verify the operator's identity.
    //     agg_nonces: Vec<MusigAggNonce>, // This includes all the agg_nonces for the bridge operations.
    // ) -> Result<(Vec<MusigPartialSignature>, Vec<MusigPartialSignature>), BridgeError> {
    //     tracing::debug!(
    //         "Operatos kickoffs generated is called with data: {:?}, {:?}, {:?}, {:?}",
    //         deposit_outpoint,
    //         kickoff_utxos,
    //         operators_kickoff_sigs,
    //         agg_nonces
    //     );

    //     if operators_kickoff_sigs.len() != kickoff_utxos.len() {
    //         return Err(BridgeError::InvalidKickoffUtxo); // TODO: Better error
    //     }

    //     let mut slash_or_take_sighashes = Vec::new();

    //     for (i, kickoff_utxo) in kickoff_utxos.iter().enumerate() {
    //         let value = kickoff_utxo.txout.value;
    //         if value < KICKOFF_UTXO_AMOUNT_SATS {
    //             return Err(BridgeError::InvalidKickoffUtxo);
    //         }

    //         let kickoff_sig_hash = crate::sha256_hash!(
    //             deposit_outpoint.txid,
    //             deposit_outpoint.vout.to_be_bytes(),
    //             kickoff_utxo.outpoint.txid,
    //             kickoff_utxo.outpoint.vout.to_be_bytes()
    //         );

    //         // Check if they are really the operators that sent these kickoff_utxos
    //         utils::SECP.verify_schnorr(
    //             &operators_kickoff_sigs[i],
    //             &bitcoin::secp256k1:: Message::from_digest(kickoff_sig_hash),
    //             &self.config.operators_xonly_pks[i],
    //         )?;

    //         // Check if for each operator the address of the kickoff_utxo is correct TODO: Maybe handle the possible errors better
    //         let (musig2_and_operator_address, spend_info) =
    //             builder::address::create_kickoff_address(
    //                 self.nofn_xonly_pk,
    //                 self.operator_xonly_pks[i],
    //                 self.config.network,
    //             );
    //         tracing::debug!(
    //             "musig2_and_operator_address.script_pubkey: {:?}",
    //             musig2_and_operator_address.script_pubkey()
    //         );
    //         tracing::debug!("Kickoff UTXO: {:?}", kickoff_utxo.txout.script_pubkey);
    //         tracing::debug!("Spend Info: {:?}", spend_info);
    //         assert!(
    //             kickoff_utxo.txout.script_pubkey == musig2_and_operator_address.script_pubkey()
    //         );

    //         let mut slash_or_take_tx_handler = builder::transaction::create_slash_or_take_tx(
    //             deposit_outpoint,
    //             kickoff_utxo.clone(),
    //             self.config.operators_xonly_pks[i],
    //             i,
    //             self.nofn_xonly_pk,
    //             self.config.network,
    //             self.config.user_takes_after,
    //             self.config.operator_takes_after,
    //             self.config.bridge_amount_sats,
    //         );
    //         let slash_or_take_tx_sighash =
    //             Actor::convert_tx_to_sighash_script_spend(&mut slash_or_take_tx_handler, 0, 0)?;
    //         slash_or_take_sighashes.push(Message::from_digest(slash_or_take_tx_sighash.to_byte_array())?);
    //         // let spend_kickoff_utxo_tx_handler = builder::transaction::create_slash_or_take_tx(deposit_outpoint, kickoff_outpoint, kickoff_txout, operator_address, operator_idx, nofn_xonly_pk, network)
    //     }
    //     tracing::debug!(
    //         "Slash or take sighashes for verifier: {:?}: {:?}",
    //         self.signer.xonly_public_key.to_string(),
    //         slash_or_take_sighashes
    //     );

    //     let mut dbtx = self.db.begin_transaction().await?;

    //     self.db
    //         .save_agg_nonces(Some(&mut dbtx), deposit_outpoint, &agg_nonces)
    //         .await?;

    //     self.db
    //         .save_kickoff_utxos(Some(&mut dbtx), deposit_outpoint, &kickoff_utxos)
    //         .await?;

    //     let nonces = self
    //         .db
    //         .save_sighashes_and_get_nonces(
    //             Some(&mut dbtx),
    //             deposit_outpoint,
    //             self.config.num_operators + 1,
    //             &slash_or_take_sighashes,
    //         )
    //         .await?
    //         .ok_or(BridgeError::NoncesNotFound)?;
    //     tracing::debug!(
    //         "SIGNING slash or take for outpoint: {:?} with nonces {:?}",
    //         deposit_outpoint,
    //         nonces
    //     );
    //     let slash_or_take_partial_sigs = slash_or_take_sighashes
    //         .iter()
    //         .zip(nonces.into_iter())
    //         .map(|(sighash, (sec_nonce, agg_nonce))| {
    //             musig2::partial_sign(
    //                 self.config.verifiers_public_keys.clone(),
    //                 None,
    //                 false,
    //                 *sec_nonce,
    //                 *agg_nonce,
    //                 &self.signer.keypair,
    //                 *sighash,
    //             )
    //         })
    //         .collect::<Vec<_>>();

    //     dbtx.commit().await?;

    //     // TODO: Sign burn txs
    //     Ok((slash_or_take_partial_sigs, vec![]))
    // }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn create_deposit_details(
        &self,
        deposit_outpoint: OutPoint,
    ) -> Result<(Vec<UTXO>, TxHandler<Unsigned>, OutPoint), BridgeError> {
        let kickoff_utxos = self
            .db
            .get_kickoff_utxos(deposit_outpoint)
            .await?
            .ok_or(BridgeError::KickoffOutpointsNotFound)?;

        // let kickoff_outpoints = kickoff_utxos
        //     .iter()
        //     .map(|utxo| utxo.outpoint)
        //     .collect::<Vec<_>>();

        let (recovery_taproot_address, evm_address) = self
            .db
            .get_deposit_info(deposit_outpoint)
            .await?
            .ok_or(BridgeError::DepositInfoNotFound)?;

        let move_tx_handler = builder::transaction::create_move_to_vault_txhandler(
            deposit_outpoint,
            evm_address,
            &recovery_taproot_address,
            self.nofn_xonly_pk,
            self.config.user_takes_after,
            self.config.bridge_amount_sats,
            self.config.network,
        )?;

        let bridge_fund_outpoint = OutPoint {
            txid: *move_tx_handler.get_txid(),
            vout: 0,
        };
        Ok((kickoff_utxos, move_tx_handler, bridge_fund_outpoint))
    }

    pub async fn set_operator_keys(
        &self,
        deposit_id: DepositData,
        keys: OperatorKeys,
        operator_idx: u32,
    ) -> Result<(), BridgeError> {
        let hashes: Vec<[u8; 20]> = keys
            .challenge_ack_digests
            .into_iter()
            .map(|x| {
                x.hash
                    .try_into()
                    .map_err(|_| BridgeError::Error("Invalid hash length".to_string()))
            })
            .collect::<Result<Vec<[u8; 20]>, BridgeError>>()?;

        if hashes.len() != self.config.get_num_challenge_ack_hashes() {
            return Err(BridgeError::Error(
                format!(
                    "Invalid number of challenge ack hashes received from operator {}: got: {} expected: {}",
                    operator_idx,
                    hashes.len(),
                    self.config.get_num_challenge_ack_hashes()
                )
            ));
        }

        let operator_data = self
            .db
            .get_operator(None, operator_idx as i32)
            .await?
            .ok_or(BridgeError::OperatorNotFound(operator_idx))?;

        self.db
            .set_operator_challenge_ack_hashes(
                None,
                operator_idx as i32,
                deposit_id.deposit_outpoint,
                &hashes,
            )
            .await?;

        let winternitz_keys: Vec<winternitz::PublicKey> = keys
            .winternitz_pubkeys
            .into_iter()
            .map(|x| x.try_into())
            .collect::<Result<_, BridgeError>>()?;

        if winternitz_keys.len() != self.config.get_num_assert_winternitz_pks() {
            return Err(BridgeError::Error(format!(
                "Invalid number of winternitz keys received from operator {}: got: {} expected: {}",
                operator_idx,
                winternitz_keys.len(),
                self.config.get_num_assert_winternitz_pks()
            )));
        }

        let mut steps_iter = utils::BITVM_CACHE.intermediate_variables.iter();

        let assert_tx_addrs: Vec<[u8; 32]> = utils::COMBINED_ASSERT_DATA
            .num_steps
            .iter()
            .map(|steps| {
                let len = steps.1 - steps.0;
                let intermediate_steps = Vec::from_iter(steps_iter.by_ref().take(len));
                let sizes: Vec<u32> = intermediate_steps
                    .iter()
                    .map(|(_, intermediate_step_size)| **intermediate_step_size as u32 * 2)
                    .collect();

                let script = WinternitzCommit::new(
                    winternitz_keys[steps.0..steps.1]
                        .iter()
                        .zip(sizes.iter())
                        .map(|(k, s)| (k.clone(), *s))
                        .collect::<Vec<_>>(),
                    operator_data.xonly_pk,
                );
                let taproot_builder = taproot_builder_with_scripts(&[script.to_script_buf()]);
                taproot_builder
                    .try_into_taptree()
                    .expect("taproot builder always builds a full taptree")
                    .root_hash()
                    .to_raw_hash()
                    .to_byte_array()
            })
            .collect::<Vec<_>>();

        // TODO: Use correct verification key and along with a dummy proof.
        let scripts: Vec<ScriptBuf> = {
            tracing::info!("Replacing disprove scripts");
            utils::replace_disprove_scripts(&winternitz_keys)
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
                deposit_id.deposit_outpoint,
                &assert_tx_addrs,
                &root_hash_bytes,
            )
            .await?;

        Ok(())
    }

    pub async fn set_watchtower_keys(
        &self,
        deposit_id: DepositData,
        keys: WatchtowerKeys,
        watchtower_idx: u32,
    ) -> Result<(), BridgeError> {
        let watchtower_xonly_pk = self
            .db
            .get_watchtower_xonly_pk(None, watchtower_idx)
            .await?;

        let winternitz_keys: Vec<winternitz::PublicKey> = keys
            .winternitz_pubkeys
            .into_iter()
            .map(|x| x.try_into())
            .collect::<Result<_, BridgeError>>()?;

        for (operator_id, winternitz_key) in winternitz_keys.iter().enumerate() {
            self.db
                .set_watchtower_winternitz_public_keys(
                    None,
                    watchtower_idx,
                    operator_id as u32,
                    deposit_id.deposit_outpoint,
                    winternitz_key,
                )
                .await?;
            let challenge_addr = derive_challenge_address_from_xonlypk_and_wpk(
                &watchtower_xonly_pk,
                vec![(winternitz_key.clone(), WATCHTOWER_CHALLENGE_MESSAGE_LENGTH)],
                self.config.network,
            )
            .script_pubkey();
            self.db
                .set_watchtower_challenge_address(
                    None,
                    watchtower_idx,
                    operator_id as u32,
                    &challenge_addr,
                    deposit_id.deposit_outpoint,
                )
                .await?;
        }

        Ok(())
    }

    // / verify burn txs are signed by verifiers
    // / sign operator_takes_txs
    // / TODO: Change the name of this function.
    // #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    // pub async fn burn_txs_signed(
    //     &self,
    //     deposit_outpoint: OutPoint,
    //     _burn_sigs: Vec<schnorr::Signature>,
    //     slash_or_take_sigs: Vec<schnorr::Signature>,
    // ) -> Result<Vec<MusigPartialSignature>, BridgeError> {
    //     // TODO: Verify burn txs are signed by verifiers
    //     let (kickoff_utxos, _, bridge_fund_outpoint) =
    //         self.create_deposit_details(deposit_outpoint).await?;

    //     let operator_takes_sighashes = kickoff_utxos
    //         .iter()
    //         .enumerate()
    //         .map(|(index, kickoff_utxo)| {
    //             let mut slash_or_take_tx_handler = builder::transaction::create_slash_or_take_tx(
    //                 deposit_outpoint,
    //                 kickoff_utxo.clone(),
    //                 self.operator_xonly_pks[index],
    //                 index,
    //                 self.nofn_xonly_pk,
    //                 self.config.network,
    //                 self.config.user_takes_after,
    //                 self.config.operator_takes_after,
    //                 self.config.bridge_amount_sats,
    //             );
    //             let slash_or_take_sighash =
    //                 Actor::convert_tx_to_sighash_script_spend(&mut slash_or_take_tx_handler, 0, 0)
    //                     .unwrap();

    //             utils::SECP
    //                 .verify_schnorr(
    //                     &slash_or_take_sigs[index],
    //                     &bitcoin::secp256k1:: Message::from_digest(slash_or_take_sighash.to_byte_array()),
    //                     &self.nofn_xonly_pk,
    //                 )
    //                 .unwrap();

    //             let slash_or_take_utxo = UTXO {
    //                 outpoint: OutPoint {
    //                     txid: slash_or_take_tx_handler.tx.compute_txid(),
    //                     vout: 0,
    //                 },
    //                 txout: slash_or_take_tx_handler.tx.output[0].clone(),
    //             };

    //             let mut operator_takes_tx = builder::transaction::create_operator_takes_tx(
    //                 bridge_fund_outpoint,
    //                 slash_or_take_utxo,
    //                 self.operator_xonly_pks[index],
    //                 self.nofn_xonly_pk,
    //                 self.config.network,
    //                 self.config.operator_takes_after,
    //                 self.config.bridge_amount_sats,
    //                 self.config.operator_wallet_addresses[index].clone(),
    //             );
    //             Message::from_digest(
    //                 Actor::convert_tx_to_sighash_pubkey_spend(&mut operator_takes_tx, 0)
    //                     .unwrap()
    //                     .to_byte_array(),
    //             )
    //         })
    //         .collect::<Vec<_>>();

    //     self.db
    //         .save_slash_or_take_sigs(deposit_outpoint, slash_or_take_sigs)
    //         .await?;

    //     // println!("Operator takes sighashes: {:?}", operator_takes_sighashes);
    //     let nonces = self
    //         .db
    //         .save_sighashes_and_get_nonces(None, deposit_outpoint, 1, &operator_takes_sighashes)
    //         .await?
    //         .ok_or(BridgeError::NoncesNotFound)?;
    //     // println!("Nonces: {:?}", nonces);
    //     // now iterate over nonces and sighashes and sign the operator_takes_txs
    //     let operator_takes_partial_sigs = operator_takes_sighashes
    //         .iter()
    //         .zip(nonces.iter())
    //         .map(|(sighash, (sec_nonce, agg_nonce))| {
    //             musig2::partial_sign(
    //                 self.config.verifiers_public_keys.clone(),
    //                 None,
    //                 true,
    //                 *sec_nonce,
    //                 *agg_nonce,
    //                 &self.signer.keypair,
    //                 *sighash,
    //             )
    //         })
    //         .collect::<Vec<_>>();

    //     Ok(operator_takes_partial_sigs)
    // }

    // / verify the operator_take_sigs
    // / sign move_tx
    // #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    // pub async fn operator_take_txs_signed(
    //     &self,
    //     deposit_outpoint: OutPoint,
    //     operator_take_sigs: Vec<schnorr::Signature>,
    // ) -> Result<MusigPartialSignature, BridgeError> {
    //     // println!("Operator take signed: {:?}", operator_take_sigs);
    //     let (kickoff_utxos, mut move_tx_handler, bridge_fund_outpoint) =
    //         self.create_deposit_details(deposit_outpoint).await?;
    //     let nofn_taproot_xonly_pk = bitcoin::secp256k1:: XOnlyPublicKey::from_slice(
    //         &Address::p2tr(&utils::SECP, self.nofn_xonly_pk, None, self.config.network)
    //             .script_pubkey()
    //             .as_bytes()[2..34],
    //     )?;
    //     kickoff_utxos
    //         .iter()
    //         .enumerate()
    //         .for_each(|(index, kickoff_utxo)| {
    //             let slash_or_take_tx = builder::transaction::create_slash_or_take_tx(
    //                 deposit_outpoint,
    //                 kickoff_utxo.clone(),
    //                 self.operator_xonly_pks[index],
    //                 index,
    //                 self.nofn_xonly_pk,
    //                 self.config.network,
    //                 self.config.user_takes_after,
    //                 self.config.operator_takes_after,
    //                 self.config.bridge_amount_sats,
    //             );
    //             let slash_or_take_utxo = UTXO {
    //                 outpoint: OutPoint {
    //                     txid: slash_or_take_tx.tx.compute_txid(),
    //                     vout: 0,
    //                 },
    //                 txout: slash_or_take_tx.tx.output[0].clone(),
    //             };
    //             let mut operator_takes_tx = builder::transaction::create_operator_takes_tx(
    //                 bridge_fund_outpoint,
    //                 slash_or_take_utxo,
    //                 self.operator_xonly_pks[index],
    //                 self.nofn_xonly_pk,
    //                 self.config.network,
    //                 self.config.operator_takes_after,
    //                 self.config.bridge_amount_sats,
    //                 self.config.operator_wallet_addresses[index].clone(),
    //             );
    //             tracing::debug!(
    //                 "INDEXXX: {:?} Operator takes tx hex: {:?}",
    //                 index,
    //                 operator_takes_tx.tx.raw_hex()
    //             );

    //             let sig_hash =
    //                 Actor::convert_tx_to_sighash_pubkey_spend(&mut operator_takes_tx, 0).unwrap();

    //             // verify the operator_take_sigs
    //             utils::SECP
    //                 .verify_schnorr(
    //                     &operator_take_sigs[index],
    //                     &bitcoin::secp256k1:: Message::from_digest(sig_hash.to_byte_array()),
    //                     &nofn_taproot_xonly_pk,
    //                 )
    //                 .unwrap();
    //         });

    //     let kickoff_utxos = kickoff_utxos
    //         .into_iter()
    //         .enumerate()
    //         .map(|(index, utxo)| (utxo, operator_take_sigs[index]));

    //     self.db
    //         .save_operator_take_sigs(deposit_outpoint, kickoff_utxos)
    //         .await?;

    //     // println!("MOVE_TX: {:?}", move_tx_handler);
    //     // println!("MOVE_TXID: {:?}", move_tx_handler.tx.compute_txid());
    //     let move_tx_sighash =
    //         Actor::convert_tx_to_sighash_script_spend(&mut move_tx_handler, 0, 0)?; // TODO: This should be musig

    //     // let move_reveal_sighash =
    //     //     Actor::convert_tx_to_sighash_script_spend(&mut move_reveal_tx_handler, 0, 0)?; // TODO: This should be musig

    //     let nonces = self
    //         .db
    //         .save_sighashes_and_get_nonces(
    //             None,
    //             deposit_outpoint,
    //             0,
    //             &[ByteArray32(move_tx_sighash.to_byte_array())],
    //         )
    //         .await?
    //         .ok_or(BridgeError::NoncesNotFound)?;

    //     let move_tx_sig = musig2::partial_sign(
    //         self.config.verifiers_public_keys.clone(),
    //         None,
    //         false,
    //         nonces[0].0,
    //         nonces[0].1,
    //         &self.signer.keypair,
    //         ByteArray32(move_tx_sighash.to_byte_array()),
    //     );

    //     // let move_reveal_sig = musig2::partial_sign(
    //     //     self.config.verifiers_public_keys.clone(),
    //     //     None,
    //     //     nonces[1].0,
    //     //     nonces[2].1.clone(),
    //     //     &self.signer.keypair,
    //     //     move_reveal_sighash.to_byte_array(),
    //     // );

    //     Ok(
    //         move_tx_sig as MusigPartialSignature, // move_reveal_sig as MuSigPartialSignature,
    //     )
    // }

    // / verify burn txs are signed by verifiers
    // / sign operator_takes_txs
    // / TODO: Change the name of this function.
    // #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    // pub async fn burn_txs_signed(
    //     &self,
    //     deposit_outpoint: OutPoint,
    //     _burn_sigs: Vec<schnorr::Signature>,
    //     slash_or_take_sigs: Vec<schnorr::Signature>,
    // ) -> Result<Vec<MuSigPartialSignature>, BridgeError> {
    //     // TODO: Verify burn txs are signed by verifiers
    //     let (kickoff_utxos, _, bridge_fund_outpoint) =
    //         self.create_deposit_details(deposit_outpoint).await?;

    //     let operator_takes_sighashes: Vec<MuSigSigHash> = kickoff_utxos
    //         .iter()
    //         .enumerate()
    //         .map(|(index, kickoff_utxo)| {
    //             let mut slash_or_take_tx_handler = builder::transaction::create_slash_or_take_tx(
    //                 deposit_outpoint,
    //                 kickoff_utxo.clone(),
    //                 self.operator_xonly_pks[index],
    //                 index,
    //                 self.nofn_xonly_pk,
    //                 self.config.network,
    //                 self.config.user_takes_after,
    //                 self.config.operator_takes_after,
    //                 self.config.bridge_amount_sats,
    //             );
    //             let slash_or_take_sighash =
    //                 Actor::convert_tx_to_sighash_script_spend(&mut slash_or_take_tx_handler, 0, 0)
    //                     .unwrap();

    //             &SECP
    //                 .verify_schnorr(
    //                     &slash_or_take_sigs[index],
    //                     &bitcoin::secp256k1:: Message::from_digest(slash_or_take_sighash.to_byte_array()),
    //                     &self.nofn_xonly_pk,
    //                 )
    //                 .unwrap();

    //             let slash_or_take_utxo = UTXO {
    //                 outpoint: OutPoint {
    //                     txid: slash_or_take_tx_handler.tx.compute_txid(),
    //                     vout: 0,
    //                 },
    //                 txout: slash_or_take_tx_handler.tx.output[0].clone(),
    //             };

    //             let mut operator_takes_tx = builder::transaction::create_operator_takes_tx(
    //                 bridge_fund_outpoint,
    //                 slash_or_take_utxo,
    //                 self.operator_xonly_pks[index],
    //                 self.nofn_xonly_pk,
    //                 self.config.network,
    //                 self.config.operator_takes_after,
    //                 self.config.bridge_amount_sats,
    //                 self.config.operator_wallet_addresses[index].clone(),
    //             );
    //             ByteArray32(
    //                 Actor::convert_tx_to_sighash_pubkey_spend(&mut operator_takes_tx, 0)
    //                     .unwrap()
    //                     .to_byte_array(),
    //             )
    //         })
    //         .collect::<Vec<_>>();

    //     self.db
    //         .save_slash_or_take_sigs(deposit_outpoint, slash_or_take_sigs)
    //         .await?;

    //     // println!("Operator takes sighashes: {:?}", operator_takes_sighashes);
    //     let nonces = self
    //         .db
    //         .save_sighashes_and_get_nonces(None, deposit_outpoint, 1, &operator_takes_sighashes)
    //         .await?
    //         .ok_or(BridgeError::NoncesNotFound)?;
    //     // println!("Nonces: {:?}", nonces);
    //     // now iterate over nonces and sighashes and sign the operator_takes_txs
    //     let operator_takes_partial_sigs = operator_takes_sighashes
    //         .iter()
    //         .zip(nonces.iter())
    //         .map(|(sighash, (sec_nonce, agg_nonce))| {
    //             musig2::partial_sign(
    //                 self.config.verifiers_public_keys.clone(),
    //                 None,
    //                 true,
    //                 *sec_nonce,
    //                 *agg_nonce,
    //                 &self.signer.keypair,
    //                 *sighash,
    //             )
    //         })
    //         .collect::<Vec<_>>();

    //     Ok(operator_takes_partial_sigs)
    // }

    // /// verify the operator_take_sigs
    // /// sign move_tx
    // #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    // pub async fn operator_take_txs_signed(
    //     &self,
    //     deposit_outpoint: OutPoint,
    //     operator_take_sigs: Vec<schnorr::Signature>,
    // ) -> Result<MuSigPartialSignature, BridgeError> {
    //     // println!("Operator take signed: {:?}", operator_take_sigs);
    //     let (kickoff_utxos, mut move_tx_handler, bridge_fund_outpoint) =
    //         self.create_deposit_details(deposit_outpoint).await?;
    //     let nofn_taproot_xonly_pk = bitcoin::secp256k1:: XOnlyPublicKey::from_slice(
    //         &Address::p2tr(&SECP, self.nofn_xonly_pk, None, self.config.network)
    //             .script_pubkey()
    //             .as_bytes()[2..34],
    //     )?;
    //     kickoff_utxos
    //         .iter()
    //         .enumerate()
    //         .for_each(|(index, kickoff_utxo)| {
    //             let slash_or_take_tx = builder::transaction::create_slash_or_take_tx(
    //                 deposit_outpoint,
    //                 kickoff_utxo.clone(),
    //                 self.operator_xonly_pks[index],
    //                 index,
    //                 self.nofn_xonly_pk,
    //                 self.config.network,
    //                 self.config.user_takes_after,
    //                 self.config.operator_takes_after,
    //                 self.config.bridge_amount_sats,
    //             );
    //             let slash_or_take_utxo = UTXO {
    //                 outpoint: OutPoint {
    //                     txid: slash_or_take_tx.tx.compute_txid(),
    //                     vout: 0,
    //                 },
    //                 txout: slash_or_take_tx.tx.output[0].clone(),
    //             };
    //             let mut operator_takes_tx = builder::transaction::create_operator_takes_tx(
    //                 bridge_fund_outpoint,
    //                 slash_or_take_utxo,
    //                 self.operator_xonly_pks[index],
    //                 self.nofn_xonly_pk,
    //                 self.config.network,
    //                 self.config.operator_takes_after,
    //                 self.config.bridge_amount_sats,
    //                 self.config.operator_wallet_addresses[index].clone(),
    //             );
    //             tracing::debug!(
    //                 "INDEXXX: {:?} Operator takes tx hex: {:?}",
    //                 index,
    //                 operator_takes_tx.tx.raw_hex()
    //             );

    //             let sig_hash =
    //                 Actor::convert_tx_to_sighash_pubkey_spend(&mut operator_takes_tx, 0).unwrap();

    //             // verify the operator_take_sigs
    //             &SECP
    //                 .verify_schnorr(
    //                     &operator_take_sigs[index],
    //                     &bitcoin::secp256k1:: Message::from_digest(sig_hash.to_byte_array()),
    //                     &nofn_taproot_xonly_pk,
    //                 )
    //                 .unwrap();
    //         });

    //     let kickoff_utxos = kickoff_utxos
    //         .into_iter()
    //         .enumerate()
    //         .map(|(index, utxo)| (utxo, operator_take_sigs[index]));

    //     self.db
    //         .save_operator_take_sigs(deposit_outpoint, kickoff_utxos)
    //         .await?;

    //     // println!("MOVE_TX: {:?}", move_tx_handler);
    //     // println!("MOVE_TXID: {:?}", move_tx_handler.tx.compute_txid());
    //     let move_tx_sighash =
    //         Actor::convert_tx_to_sighash_script_spend(&mut move_tx_handler, 0, 0)?; // TODO: This should be musig

    //     // let move_reveal_sighash =
    //     //     Actor::convert_tx_to_sighash_script_spend(&mut move_reveal_tx_handler, 0, 0)?; // TODO: This should be musig

    //     let nonces = self
    //         .db
    //         .save_sighashes_and_get_nonces(
    //             None,
    //             deposit_outpoint,
    //             0,
    //             &[ByteArray32(move_tx_sighash.to_byte_array())],
    //         )
    //         .await?
    //         .ok_or(BridgeError::NoncesNotFound)?;

    //     let move_tx_sig = musig2::partial_sign(
    //         self.config.verifiers_public_keys.clone(),
    //         None,
    //         false,
    //         nonces[0].0,
    //         nonces[0].1,
    //         &self.signer.keypair,
    //         ByteArray32(move_tx_sighash.to_byte_array()),
    //     );

    //     // let move_reveal_sig = musig2::partial_sign(
    //     //     self.config.verifiers_public_keys.clone(),
    //     //     None,
    //     //     nonces[1].0,
    //     //     nonces[2].1.clone(),
    //     //     &self.signer.keypair,
    //     //     move_reveal_sighash.to_byte_array(),
    //     // );

    //     Ok(
    //         move_tx_sig as MuSigPartialSignature, // move_reveal_sig as MuSigPartialSignature,
    //     )
    // }
}

// #[cfg(test)]
// mod tests {
// use crate::errors::BridgeError;
// use crate::extended_rpc::ExtendedRpc;
// use crate::musig2::nonce_pair;
// use crate::user::User;
// use crate::verifier::Verifier;
// use crate::EVMAddress;
// use crate::{actor::Actor, create_test_config_with_thread_name};
// use crate::{
//     config::BridgeConfig, database::Database, test::common::*, utils::initialize_logger,
// };
// use bitcoin::secp256k1:: rand;
// use std::{env, thread};

// #[tokio::test]
// async fn verifier_new_public_key_check() {
//     let mut config = create_test_config_with_thread_name(None).await;
//     let rpc = ExtendedRpc::connect(
//         config.bitcoin_rpc_url.clone(),
//         config.bitcoin_rpc_user.clone(),
//         config.bitcoin_rpc_password.clone(),
//     )
//     .await;

//     // Test config file has correct keys.
//     Verifier::new(rpc.clone_inner().await.unwrap(), config.clone()).await.unwrap();

//     // Clearing them should result in error.
//     config.verifiers_public_keys.clear();
//     assert!(Verifier::new(rpc, config).await.is_err());
// }

// #[tokio::test]
//
// async fn new_deposit_nonce_checks() {
//     let mut config = create_test_config_with_thread_name(None).await;
//     let rpc = ExtendedRpc::connect(
//         config.bitcoin_rpc_url.clone(),
//         config.bitcoin_rpc_user.clone(),
//         config.bitcoin_rpc_password.clone(),
//     )
//     .await;
//     let verifier = Verifier::new(rpc.clone_inner().await.unwrap(), config.clone()).await.unwrap();

//     let evm_address = EVMAddress([1u8; 20]);
//     let deposit_address = get_deposit_address(config, evm_address).unwrap(); This line needs to be converted into get_deposit_address

//     let signer_address = Actor::new(
//         config.secret_key,
//         config.winternitz_secret_key,
//         config.network,
//     )
//     .address
//     .as_unchecked()
//     .clone();

//     let required_nonce_count = 2 * config.operators_xonly_pks.len() + 1;

//     // Not enough nonces.
//     let deposit_outpoint = rpc
//         .send_to_address(&deposit_address.clone(), config.bridge_amount_sats)
//         .await
//         .unwrap();
//     rpc.mine_blocks((config.confirmation_threshold + 2).into())
//         .await
//         .unwrap();

//     let nonces = (0..required_nonce_count / 2)
//         .map(|_| nonce_pair(&verifier.signer.keypair, &mut rand::rngs::OsRng))
//         .collect::<Vec<_>>();
//     verifier
//         .db
//         .save_nonces(None, deposit_outpoint, &nonces)
//         .await
//         .unwrap();

//     assert!(verifier
//         .new_deposit(deposit_outpoint, signer_address.clone(), evm_address)
//         .await
//         .is_err_and(|e| {
//             if let BridgeError::NoncesNotFound = e {
//                 true
//             } else {
//                 println!("Error was {e}");
//                 false
//             }
//         }));

//     // Enough nonces.
//     let deposit_outpoint = rpc
//         .send_to_address(&deposit_address.clone(), config.bridge_amount_sats)
//         .await
//         .unwrap();
//     rpc.mine_blocks((config.confirmation_threshold + 2).into())
//         .await
//         .unwrap();

//     let nonces = (0..required_nonce_count)
//         .map(|_| nonce_pair(&verifier.signer.keypair, &mut rand::rngs::OsRng))
//         .collect::<Vec<_>>();
//     verifier
//         .db
//         .save_nonces(None, deposit_outpoint, &nonces)
//         .await
//         .unwrap();

//     verifier
//         .new_deposit(deposit_outpoint, signer_address, evm_address)
//         .await
//         .unwrap();
// }
// }
