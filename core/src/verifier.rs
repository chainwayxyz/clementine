use crate::actor::Actor;
use crate::config::BridgeConfig;
use crate::database::verifier::VerifierDB;
use crate::errors::BridgeError;
use crate::extended_rpc::ExtendedRpc;
use crate::musig2::{
    self, AggregateFromPublicKeys, MuSigAggNonce, MuSigPartialSignature, MuSigPubNonce,
    MuSigSigHash,
};
use crate::traits::rpc::VerifierRpcServer;
use crate::transaction_builder::{TransactionBuilder, TxHandler, KICKOFF_UTXO_AMOUNT_SATS};
use crate::{utils, ByteArray32, ByteArray64, ByteArray66, EVMAddress, UTXO};
use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::Hash;
use bitcoin::Address;
use bitcoin::{secp256k1, OutPoint};
use bitcoin_mock_rpc::RpcApiWrapper;
use bitcoincore_rpc::RawTx;
use jsonrpsee::core::async_trait;
use secp256k1::{rand, schnorr};

#[derive(Debug, Clone)]
pub struct Verifier<R>
where
    R: RpcApiWrapper,
{
    rpc: ExtendedRpc<R>,
    signer: Actor,
    db: VerifierDB,
    config: BridgeConfig,
    nofn_xonly_pk: secp256k1::XOnlyPublicKey,
    operator_xonly_pks: Vec<secp256k1::XOnlyPublicKey>,
}

impl<R> Verifier<R>
where
    R: RpcApiWrapper,
{
    pub async fn new(rpc: ExtendedRpc<R>, config: BridgeConfig) -> Result<Self, BridgeError> {
        let signer = Actor::new(config.secret_key, config.bitcoin.network);

        let pk: secp256k1::PublicKey = config.secret_key.public_key(&utils::SECP);

        // Generated public key must be in given public key list.
        if !config.verifier.public_keys.contains(&pk) {
            return Err(BridgeError::PublicKeyNotFound);
        }

        let db = VerifierDB::new(config.clone()).await;

        let nofn_xonly_pk = secp256k1::XOnlyPublicKey::from_musig2_pks(
            config.verifier.public_keys.clone(),
            None,
            false,
        );

        let operator_xonly_pks = config.operator.xonly_pks.clone();

        Ok(Verifier {
            rpc,
            signer,
            db,
            config,
            nofn_xonly_pk,
            operator_xonly_pks,
        })
    }

    /// Inform verifiers about the new deposit request
    ///
    /// 1. Check if the deposit UTXO is valid, finalized (6 blocks confirmation) and not spent
    /// 2. Generate random pubNonces, secNonces
    /// 3. Save pubNonces and secNonces to a db
    /// 4. Return pubNonces
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn new_deposit(
        &self,
        deposit_outpoint: OutPoint,
        recovery_taproot_address: Address<NetworkUnchecked>,
        evm_address: EVMAddress,
    ) -> Result<Vec<MuSigPubNonce>, BridgeError> {
        self.rpc.check_deposit_utxo(
            &self.nofn_xonly_pk,
            &deposit_outpoint,
            &recovery_taproot_address,
            &evm_address,
            self.config.bridge_amount_sats,
            self.config.confirmation_threshold,
            self.config.bitcoin.network,
            self.config.user_takes_after,
        )?;

        // For now we multiply by 2 since we do not give signatures for burn_txs. // TODO: Change this in future.
        let num_required_nonces = 2 * self.operator_xonly_pks.len() + 1;

        let mut dbtx = self.db.begin_transaction().await?;
        // Check if we already have pub_nonces for this deposit_outpoint.
        let pub_nonces_from_db = self
            .db
            .get_pub_nonces(Some(&mut dbtx), deposit_outpoint)
            .await?;
        if let Some(pub_nonces) = pub_nonces_from_db {
            if !pub_nonces.is_empty() {
                if pub_nonces.len() != num_required_nonces {
                    return Err(BridgeError::NoncesNotFound);
                }
                dbtx.commit().await?;
                return Ok(pub_nonces);
            }
        }

        let nonces = (0..num_required_nonces)
            .map(|_| musig2::nonce_pair(&self.signer.keypair, &mut rand::rngs::OsRng))
            .collect::<Vec<_>>();
        let nonces: Vec<(ByteArray64, ByteArray66)> = nonces
            .into_iter()
            .collect::<Vec<(ByteArray64, ByteArray66)>>();

        self.db
            .save_deposit_info(
                Some(&mut dbtx),
                deposit_outpoint,
                recovery_taproot_address,
                evm_address,
            )
            .await?;
        self.db
            .save_nonces(Some(&mut dbtx), deposit_outpoint, &nonces)
            .await?;
        dbtx.commit().await?;

        let pub_nonces = nonces.iter().map(|(_, pub_nonce)| *pub_nonce).collect();

        Ok(pub_nonces)
    }

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
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn operator_kickoffs_generated(
        &self,
        deposit_outpoint: OutPoint,
        kickoff_utxos: Vec<UTXO>,
        operators_kickoff_sigs: Vec<secp256k1::schnorr::Signature>, // These are not transaction signatures, rather, they are to verify the operator's identity.
        agg_nonces: Vec<MuSigAggNonce>, // This includes all the agg_nonces for the bridge operations.
    ) -> Result<(Vec<MuSigPartialSignature>, Vec<MuSigPartialSignature>), BridgeError> {
        tracing::debug!(
            "Operatos kickoffs generated is called with data: {:?}, {:?}, {:?}, {:?}",
            deposit_outpoint,
            kickoff_utxos,
            operators_kickoff_sigs,
            agg_nonces
        );

        if operators_kickoff_sigs.len() != kickoff_utxos.len() {
            return Err(BridgeError::InvalidKickoffUtxo); // TODO: Better error
        }

        let mut slash_or_take_sighashes: Vec<MuSigSigHash> = Vec::new();

        for (i, kickoff_utxo) in kickoff_utxos.iter().enumerate() {
            let value = kickoff_utxo.txout.value;
            if value.to_sat() < KICKOFF_UTXO_AMOUNT_SATS {
                return Err(BridgeError::InvalidKickoffUtxo);
            }

            let kickoff_sig_hash = crate::sha256_hash!(
                deposit_outpoint.txid,
                deposit_outpoint.vout.to_be_bytes(),
                kickoff_utxo.outpoint.txid,
                kickoff_utxo.outpoint.vout.to_be_bytes()
            );

            // Check if they are really the operators that sent these kickoff_utxos
            utils::SECP.verify_schnorr(
                &operators_kickoff_sigs[i],
                &secp256k1::Message::from_digest(kickoff_sig_hash),
                &self.config.operator.xonly_pks[i],
            )?;

            // Check if for each operator the address of the kickoff_utxo is correct TODO: Maybe handle the possible errors better
            let (musig2_and_operator_address, spend_info) =
                TransactionBuilder::create_kickoff_address(
                    &self.nofn_xonly_pk,
                    &self.operator_xonly_pks[i],
                    self.config.bitcoin.network,
                );
            tracing::debug!(
                "musig2_and_operator_address.script_pubkey: {:?}",
                musig2_and_operator_address.script_pubkey()
            );
            tracing::debug!("Kickoff UTXO: {:?}", kickoff_utxo.txout.script_pubkey);
            tracing::debug!("Spend Info: {:?}", spend_info);
            assert!(
                kickoff_utxo.txout.script_pubkey == musig2_and_operator_address.script_pubkey()
            );

            let mut slash_or_take_tx_handler = TransactionBuilder::create_slash_or_take_tx(
                deposit_outpoint,
                kickoff_utxo.clone(),
                &self.config.operator.xonly_pks[i],
                i,
                &self.nofn_xonly_pk,
                self.config.bitcoin.network,
                self.config.user_takes_after,
                self.config.operator.takes_after,
                self.config.bridge_amount_sats,
            );
            let slash_or_take_tx_sighash =
                Actor::convert_tx_to_sighash_script_spend(&mut slash_or_take_tx_handler, 0, 0)?;
            slash_or_take_sighashes.push(ByteArray32(slash_or_take_tx_sighash.to_byte_array()));
            // let spend_kickoff_utxo_tx_handler = TransactionBuilder::create_slash_or_take_tx(deposit_outpoint, kickoff_outpoint, kickoff_txout, operator_address, operator_idx, nofn_xonly_pk, network)
        }
        tracing::debug!(
            "Slash or take sighashes for verifier: {:?}: {:?}",
            self.signer.xonly_public_key.to_string(),
            slash_or_take_sighashes
        );

        let mut dbtx = self.db.begin_transaction().await?;

        self.db
            .save_agg_nonces(Some(&mut dbtx), deposit_outpoint, &agg_nonces)
            .await?;

        self.db
            .save_kickoff_utxos(Some(&mut dbtx), deposit_outpoint, &kickoff_utxos)
            .await?;

        let nonces = self
            .db
            .save_sighashes_and_get_nonces(
                Some(&mut dbtx),
                deposit_outpoint,
                self.config.operator.count + 1,
                &slash_or_take_sighashes,
            )
            .await?
            .ok_or(BridgeError::NoncesNotFound)?;
        tracing::debug!(
            "SIGNING slash or take for outpoint: {:?} with nonces {:?}",
            deposit_outpoint,
            nonces
        );
        let slash_or_take_partial_sigs = slash_or_take_sighashes
            .iter()
            .zip(nonces.iter())
            .map(|(sighash, (sec_nonce, agg_nonce))| {
                musig2::partial_sign(
                    self.config.verifier.public_keys.clone(),
                    None,
                    false,
                    *sec_nonce,
                    *agg_nonce,
                    &self.signer.keypair,
                    *sighash,
                )
            })
            .collect::<Vec<_>>();

        dbtx.commit().await?;

        // TODO: Sign burn txs
        Ok((slash_or_take_partial_sigs, vec![]))
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn create_deposit_details(
        &self,
        deposit_outpoint: OutPoint,
    ) -> Result<(Vec<UTXO>, TxHandler, OutPoint), BridgeError> {
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

        let move_tx_handler = TransactionBuilder::create_move_tx(
            deposit_outpoint,
            &evm_address,
            &recovery_taproot_address,
            &self.nofn_xonly_pk,
            self.config.bitcoin.network,
            self.config.user_takes_after,
            self.config.bridge_amount_sats,
        );

        let bridge_fund_outpoint = OutPoint {
            txid: move_tx_handler.tx.compute_txid(),
            vout: 0,
        };
        Ok((kickoff_utxos, move_tx_handler, bridge_fund_outpoint))
    }

    /// verify burn txs are signed by verifiers
    /// sign operator_takes_txs
    /// TODO: Change the name of this function.
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn burn_txs_signed(
        &self,
        deposit_outpoint: OutPoint,
        _burn_sigs: Vec<schnorr::Signature>,
        slash_or_take_sigs: Vec<schnorr::Signature>,
    ) -> Result<Vec<MuSigPartialSignature>, BridgeError> {
        // TODO: Verify burn txs are signed by verifiers
        let (kickoff_utxos, _, bridge_fund_outpoint) =
            self.create_deposit_details(deposit_outpoint).await?;

        let operator_takes_sighashes: Vec<MuSigSigHash> = kickoff_utxos
            .iter()
            .enumerate()
            .map(|(index, kickoff_utxo)| {
                let mut slash_or_take_tx_handler = TransactionBuilder::create_slash_or_take_tx(
                    deposit_outpoint,
                    kickoff_utxo.clone(),
                    &self.operator_xonly_pks[index],
                    index,
                    &self.nofn_xonly_pk,
                    self.config.bitcoin.network,
                    self.config.user_takes_after,
                    self.config.operator.takes_after,
                    self.config.bridge_amount_sats,
                );
                let slash_or_take_sighash =
                    Actor::convert_tx_to_sighash_script_spend(&mut slash_or_take_tx_handler, 0, 0)
                        .unwrap();

                utils::SECP
                    .verify_schnorr(
                        &slash_or_take_sigs[index],
                        &secp256k1::Message::from_digest(slash_or_take_sighash.to_byte_array()),
                        &self.nofn_xonly_pk,
                    )
                    .unwrap();

                let slash_or_take_utxo = UTXO {
                    outpoint: OutPoint {
                        txid: slash_or_take_tx_handler.tx.compute_txid(),
                        vout: 0,
                    },
                    txout: slash_or_take_tx_handler.tx.output[0].clone(),
                };

                let mut operator_takes_tx = TransactionBuilder::create_operator_takes_tx(
                    bridge_fund_outpoint,
                    slash_or_take_utxo,
                    &self.operator_xonly_pks[index],
                    &self.nofn_xonly_pk,
                    self.config.bitcoin.network,
                    self.config.operator.takes_after,
                    self.config.bridge_amount_sats,
                    self.config.operator_wallet_addresses[index].clone(),
                );
                ByteArray32(
                    Actor::convert_tx_to_sighash_pubkey_spend(&mut operator_takes_tx, 0)
                        .unwrap()
                        .to_byte_array(),
                )
            })
            .collect::<Vec<_>>();

        self.db
            .save_slash_or_take_sigs(deposit_outpoint, slash_or_take_sigs)
            .await?;

        // println!("Operator takes sighashes: {:?}", operator_takes_sighashes);
        let nonces = self
            .db
            .save_sighashes_and_get_nonces(None, deposit_outpoint, 1, &operator_takes_sighashes)
            .await?
            .ok_or(BridgeError::NoncesNotFound)?;
        // println!("Nonces: {:?}", nonces);
        // now iterate over nonces and sighashes and sign the operator_takes_txs
        let operator_takes_partial_sigs = operator_takes_sighashes
            .iter()
            .zip(nonces.iter())
            .map(|(sighash, (sec_nonce, agg_nonce))| {
                musig2::partial_sign(
                    self.config.verifier.public_keys.clone(),
                    None,
                    true,
                    *sec_nonce,
                    *agg_nonce,
                    &self.signer.keypair,
                    *sighash,
                )
            })
            .collect::<Vec<_>>();

        Ok(operator_takes_partial_sigs)
    }

    /// verify the operator_take_sigs
    /// sign move_tx
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn operator_take_txs_signed(
        &self,
        deposit_outpoint: OutPoint,
        operator_take_sigs: Vec<schnorr::Signature>,
    ) -> Result<MuSigPartialSignature, BridgeError> {
        // println!("Operator take signed: {:?}", operator_take_sigs);
        let (kickoff_utxos, mut move_tx_handler, bridge_fund_outpoint) =
            self.create_deposit_details(deposit_outpoint).await?;

        let _ = kickoff_utxos
            .iter()
            .enumerate()
            .map(|(index, kickoff_utxo)| {
                let slash_or_take_tx = TransactionBuilder::create_slash_or_take_tx(
                    deposit_outpoint,
                    kickoff_utxo.clone(),
                    &self.operator_xonly_pks[index],
                    index,
                    &self.nofn_xonly_pk,
                    self.config.bitcoin.network,
                    self.config.user_takes_after,
                    self.config.operator.takes_after,
                    self.config.bridge_amount_sats,
                );
                let slash_or_take_utxo = UTXO {
                    outpoint: OutPoint {
                        txid: slash_or_take_tx.tx.compute_txid(),
                        vout: 0,
                    },
                    txout: slash_or_take_tx.tx.output[0].clone(),
                };
                let mut operator_takes_tx = TransactionBuilder::create_operator_takes_tx(
                    bridge_fund_outpoint,
                    slash_or_take_utxo,
                    &self.operator_xonly_pks[index],
                    &self.nofn_xonly_pk,
                    self.config.bitcoin.network,
                    self.config.operator.takes_after,
                    self.config.bridge_amount_sats,
                    self.config.operator_wallet_addresses[index].clone(),
                );
                tracing::debug!(
                    "INDEXXX: {:?} Operator takes tx hex: {:?}",
                    index,
                    operator_takes_tx.tx.raw_hex()
                );

                let sig_hash =
                    Actor::convert_tx_to_sighash_pubkey_spend(&mut operator_takes_tx, 0).unwrap();

                // verify the operator_take_sigs
                utils::SECP
                    .verify_schnorr(
                        &operator_take_sigs[index],
                        &secp256k1::Message::from_digest(sig_hash.to_byte_array()),
                        &self.nofn_xonly_pk,
                    )
                    .unwrap();
            });

        let kickoff_utxos = kickoff_utxos
            .into_iter()
            .enumerate()
            .map(|(index, utxo)| (utxo, operator_take_sigs[index]));

        self.db
            .save_operator_take_sigs(deposit_outpoint, kickoff_utxos)
            .await?;

        // println!("MOVE_TX: {:?}", move_tx_handler);
        // println!("MOVE_TXID: {:?}", move_tx_handler.tx.compute_txid());
        let move_tx_sighash =
            Actor::convert_tx_to_sighash_script_spend(&mut move_tx_handler, 0, 0)?; // TODO: This should be musig

        // let move_reveal_sighash =
        //     Actor::convert_tx_to_sighash_script_spend(&mut move_reveal_tx_handler, 0, 0)?; // TODO: This should be musig

        let nonces = self
            .db
            .save_sighashes_and_get_nonces(
                None,
                deposit_outpoint,
                0,
                &[ByteArray32(move_tx_sighash.to_byte_array())],
            )
            .await?
            .ok_or(BridgeError::NoncesNotFound)?;

        let move_tx_sig = musig2::partial_sign(
            self.config.verifier.public_keys.clone(),
            None,
            false,
            nonces[0].0,
            nonces[0].1,
            &self.signer.keypair,
            ByteArray32(move_tx_sighash.to_byte_array()),
        );

        // let move_reveal_sig = musig2::partial_sign(
        //     self.config.verifier.public_keys.clone(),
        //     None,
        //     nonces[1].0,
        //     nonces[2].1.clone(),
        //     &self.signer.keypair,
        //     move_reveal_sighash.to_byte_array(),
        // );

        Ok(
            move_tx_sig as MuSigPartialSignature, // move_reveal_sig as MuSigPartialSignature,
        )
    }
}

#[async_trait]
impl<R> VerifierRpcServer for Verifier<R>
where
    R: RpcApiWrapper,
{
    async fn verifier_new_deposit_rpc(
        &self,
        deposit_outpoint: OutPoint,
        recovery_taproot_address: Address<NetworkUnchecked>,
        evm_address: EVMAddress,
    ) -> Result<Vec<MuSigPubNonce>, BridgeError> {
        self.new_deposit(deposit_outpoint, recovery_taproot_address, evm_address)
            .await
    }

    async fn operator_kickoffs_generated_rpc(
        &self,
        deposit_outpoint: OutPoint,
        kickoff_utxos: Vec<UTXO>,
        operators_kickoff_sigs: Vec<schnorr::Signature>,
        agg_nonces: Vec<MuSigAggNonce>,
    ) -> Result<(Vec<MuSigPartialSignature>, Vec<MuSigPartialSignature>), BridgeError> {
        self.operator_kickoffs_generated(
            deposit_outpoint,
            kickoff_utxos,
            operators_kickoff_sigs,
            agg_nonces,
        )
        .await
    }

    async fn burn_txs_signed_rpc(
        &self,
        deposit_outpoint: OutPoint,
        burn_sigs: Vec<schnorr::Signature>,
        slash_or_take_sigs: Vec<schnorr::Signature>,
    ) -> Result<Vec<MuSigPartialSignature>, BridgeError> {
        self.burn_txs_signed(deposit_outpoint, burn_sigs, slash_or_take_sigs)
            .await
    }

    async fn operator_take_txs_signed_rpc(
        &self,
        deposit_outpoint: OutPoint,
        operator_take_sigs: Vec<schnorr::Signature>,
    ) -> Result<MuSigPartialSignature, BridgeError> {
        self.operator_take_txs_signed(deposit_outpoint, operator_take_sigs)
            .await
    }
}
