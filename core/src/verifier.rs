use crate::actor::Actor;
use crate::config::BridgeConfig;
use crate::database::verifier::VerifierDB;
use crate::errors::BridgeError;
use crate::extended_rpc::ExtendedRpc;
use crate::merkle::MerkleTree;
use crate::musig2::{self, MuSigAggNonce, MuSigPartialSignature, MuSigPubNonce};
use crate::traits::rpc::VerifierRpcServer;
use crate::transaction_builder::{TransactionBuilder, TxHandler};
use crate::{script_builder, utils, EVMAddress, UTXO};
use ::musig2::secp::Point;
use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::Hash;
use bitcoin::{merkle_tree, Address};
use bitcoin::{secp256k1, OutPoint};
use bitcoin_mock_rpc::RpcApiWrapper;
use clementine_circuits::constants::BRIDGE_AMOUNT_SATS;
use clementine_circuits::incremental_merkle::IncrementalMerkleTree;
use clementine_circuits::sha256_hash;
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
    idx: usize,
    operator_xonly_pks: Vec<secp256k1::XOnlyPublicKey>,
}

impl<R> Verifier<R>
where
    R: RpcApiWrapper,
{
    pub async fn new(rpc: ExtendedRpc<R>, config: BridgeConfig) -> Result<Self, BridgeError> {
        let signer = Actor::new(config.secret_key, config.network);

        let pk: secp256k1::PublicKey = config.secret_key.public_key(&utils::SECP);

        // Generated public key must be in given public key list.
        if !config.verifiers_public_keys.contains(&pk) {
            return Err(BridgeError::PublicKeyNotFound);
        }

        let db = VerifierDB::new(config.clone()).await;

        let key_agg_context =
            musig2::create_key_agg_ctx(config.verifiers_public_keys.clone(), None)?;
        let agg_point: Point = key_agg_context.aggregated_pubkey_untweaked();
        let nofn_xonly_pk = secp256k1::XOnlyPublicKey::from_slice(&agg_point.serialize_xonly())?;
        let operator_xonly_pks = config.operators_xonly_pks.clone();
        let idx = config
            .verifiers_public_keys
            .iter()
            .position(|&x| x == pk)
            .unwrap();

        Ok(Verifier {
            rpc,
            signer,
            db,
            config,
            nofn_xonly_pk,
            idx,
            operator_xonly_pks,
        })
    }

    /// Inform verifiers about the new deposit request
    ///
    /// 1. Check if the deposit UTXO is valid, finalized (6 blocks confirmation) and not spent
    /// 2. Generate random pubNonces, secNonces
    /// 3. Save pubNonces and secNonces to a db
    /// 4. Return pubNonces
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
            BRIDGE_AMOUNT_SATS,
            self.config.user_takes_after,
            self.config.confirmation_treshold,
            self.config.network,
        )?;

        // For now we multiply by 2 since we do not give signatures for burn_txs. // TODO: Change this in future.
        let num_required_nonces = 2 * self.operator_xonly_pks.len() + 1;

        // Check if we already have pub_nonces for this deposit_utxo.
        let pub_nonces_from_db = self.db.get_pub_nonces(deposit_outpoint).await?;
        if let Some(pub_nonces) = pub_nonces_from_db {
            if pub_nonces.len() != num_required_nonces {
                return Err(BridgeError::NoncesNotFound);
            }
            return Ok(pub_nonces);
        }

        let nonces = (0..num_required_nonces)
            .map(|_| musig2::nonce_pair(&self.signer.keypair, &mut rand::rngs::OsRng))
            .collect::<Vec<_>>();

        let transaction = self.db.begin_transaction().await?;
        self.db
            .save_deposit_info(deposit_outpoint, recovery_taproot_address, evm_address)
            .await?;
        self.db.save_nonces(deposit_outpoint, &nonces).await?;
        transaction.commit().await?;

        let pub_nonces = nonces
            .iter()
            .map(|(_, pub_nonce)| pub_nonce.clone())
            .collect();

        Ok(pub_nonces)
    }

    /// - Verify operators signatures about kickoffs
    /// - Check the kickoff_utxos
    /// - Save agg_nonces to a db for future use
    /// - for every kickoff_utxo, calculate slash_or_take_tx
    /// - for every slash_or_take_tx, partial sign slash_or_take_tx
    /// - for every slash_or_take_tx, partial sign burn_tx (omitted for now)
    /// - return burn_txs partial signatures (omitted for now) TODO: For this bit,
    /// do not forget to add tweak when signing since this address has n_of_n as internal_key
    /// and operator_timelock as script.
    async fn operator_kickoffs_generated(
        &self,
        deposit_outpoint: OutPoint,
        kickoff_utxos: Vec<UTXO>,
        operators_kickoff_sigs: Vec<secp256k1::schnorr::Signature>, // These are not transaction signatures, rather, they are to verify the operator's identity.
        agg_nonces: Vec<MuSigAggNonce>, // This includes all the agg_nonces for the bridge operations.
    ) -> Result<(Vec<MuSigPartialSignature>, Vec<MuSigPartialSignature>), BridgeError> {
        if operators_kickoff_sigs.len() != kickoff_utxos.len() {
            return Err(BridgeError::InvalidKickoffUtxo); // TODO: Better error
        }

        self.db
            .save_agg_nonces(deposit_outpoint, &agg_nonces)
            .await?;

        let mut slash_or_take_sighashes: Vec<[u8; 32]> = Vec::new();

        for (i, kickoff_utxo) in kickoff_utxos.iter().enumerate() {
            let value = kickoff_utxo.txout.value;
            if value.to_sat() < 100_000 {
                return Err(BridgeError::InvalidKickoffUtxo);
            }

            let kickoff_sig_hash = sha256_hash!(
                deposit_outpoint.txid,
                deposit_outpoint.vout.to_be_bytes(),
                kickoff_utxo.outpoint.txid,
                kickoff_utxo.outpoint.vout.to_be_bytes()
            );

            // Check if they are really the operators that sent these kickoff_utxos
            utils::SECP.verify_schnorr(
                &operators_kickoff_sigs[i],
                &secp256k1::Message::from_digest(kickoff_sig_hash),
                &self.config.operators_xonly_pks[i],
            )?;

            // Check if for each operator the address of the kickoff_utxo is correct TODO: Maybe handle the possible errors better
            let (musig2_and_operator_address, _) = TransactionBuilder::create_kickoff_address(
                &self.nofn_xonly_pk,
                &self.operator_xonly_pks[i],
                self.config.network,
            );
            assert!(
                kickoff_utxo.txout.script_pubkey == musig2_and_operator_address.script_pubkey()
            );

            let mut slash_or_take_tx_handler = TransactionBuilder::create_slash_or_take_tx(
                deposit_outpoint,
                kickoff_utxo.clone(),
                &self.config.operators_xonly_pks[i],
                i,
                &self.nofn_xonly_pk,
                self.config.network,
            );
            let slash_or_take_tx_sighash =
                Actor::convert_tx_to_sighash_script_spend(&mut slash_or_take_tx_handler, 0, 0)?;
            slash_or_take_sighashes.push(slash_or_take_tx_sighash.to_byte_array());
            // let spend_kickoff_utxo_tx_handler = TransactionBuilder::create_slash_or_take_tx(deposit_outpoint, kickoff_outpoint, kickoff_txout, operator_address, operator_idx, nofn_xonly_pk, network)
        }

        let nonces = self
            .db
            .save_sighashes_and_get_nonces(
                deposit_outpoint,
                self.config.num_operators + 1,
                &slash_or_take_sighashes,
            )
            .await?
            .ok_or(BridgeError::NoncesNotFound)?;
        let slash_or_take_partial_sigs = slash_or_take_sighashes
            .iter()
            .zip(nonces.iter())
            .map(|(sighash, (sec_nonce, agg_nonce))| {
                musig2::partial_sign(
                    self.config.verifiers_public_keys.clone(),
                    None,
                    *sec_nonce,
                    agg_nonce.clone(),
                    &self.signer.keypair,
                    *sighash,
                )
            })
            .collect::<Vec<_>>();
        // let root: bitcoin::hashes::sha256::Hash = bitcoin::merkle_tree::calculate_root(
        //     kickoff_utxos
        //         .iter()
        //         .map(|utxo| Hash::from_byte_array(sha256_hash!(utxo.to_vec().as_slice()))),
        // )
        // .unwrap();
        // let root_bytes: [u8; 32] = *root.as_byte_array();

        self.db
            .save_kickoff_utxos(deposit_outpoint, &kickoff_utxos)
            .await?;

        // self.db
        //     .save_kickoff_root(deposit_outpoint, root_bytes)
        //     .await?;

        // TODO: Sign burn txs
        Ok((slash_or_take_partial_sigs, vec![]))
    }

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

        // let move_commit_tx_handler = TransactionBuilder::create_move_commit_tx(
        //     deposit_outpoint,
        //     &evm_address,
        //     &recovery_taproot_address,
        //     200, // TODO: Fix this
        //     &self.nofn_xonly_pk,
        //     &kickoff_outpoints,
        //     201, // TODO: Fix this
        //     self.config.network,
        // );

        // let move_reveal_tx_handler = TransactionBuilder::create_move_reveal_tx(
        //     OutPoint {
        //         txid: move_commit_tx_handler.tx.compute_txid(),
        //         vout: 0,
        //     },
        //     &evm_address,
        //     &recovery_taproot_address,
        //     &self.nofn_xonly_pk,
        //     &kickoff_outpoints,
        //     201, // TODO: Fix this
        //     self.config.network,
        // );

        let move_tx_handler = TransactionBuilder::create_move_tx(
            deposit_outpoint,
            &evm_address,
            &recovery_taproot_address,
            200, // TODO: Fix this
            &self.nofn_xonly_pk,
            self.config.network,
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
    async fn burn_txs_signed(
        &self,
        deposit_outpoint: OutPoint,
        _burn_sigs: Vec<schnorr::Signature>,
        slash_or_take_sigs: Vec<schnorr::Signature>,
    ) -> Result<Vec<MuSigPartialSignature>, BridgeError> {
        // TODO: Verify burn txs are signed by verifiers
        let (kickoff_utxos, _, bridge_fund_outpoint) =
            self.create_deposit_details(deposit_outpoint).await?;

        let operator_takes_sighashes = kickoff_utxos
            .iter()
            .enumerate()
            .map(|(index, kickoff_utxo)| {
                let mut slash_or_take_tx_handler = TransactionBuilder::create_slash_or_take_tx(
                    deposit_outpoint,
                    kickoff_utxo.clone(),
                    &self.operator_xonly_pks[index],
                    index,
                    &self.nofn_xonly_pk,
                    self.config.network,
                );
                let slash_or_take_sighash =
                    Actor::convert_tx_to_sighash_script_spend(&mut slash_or_take_tx_handler, 0, 0)
                        .unwrap();

                utils::SECP.verify_schnorr(
                    &slash_or_take_sigs[index],
                    &secp256k1::Message::from_digest(slash_or_take_sighash.to_byte_array()),
                    &self.nofn_xonly_pk,
                );

                let (operator_address, _) = TransactionBuilder::create_taproot_address(
                    &[],
                    Some(self.operator_xonly_pks[index]),
                    self.config.network,
                );

                let mut operator_takes_tx = TransactionBuilder::create_operator_takes_tx(
                    bridge_fund_outpoint,
                    OutPoint {
                        txid: slash_or_take_tx_handler.tx.compute_txid(),
                        vout: 0,
                    },
                    slash_or_take_tx_handler.tx.output[0].clone(),
                    &operator_address,
                    &self.nofn_xonly_pk,
                    self.config.network,
                );
                Actor::convert_tx_to_sighash_pubkey_spend(&mut operator_takes_tx, 0)
                    .unwrap()
                    .to_byte_array()
            })
            .collect::<Vec<_>>();

        let nonces = self
            .db
            .save_sighashes_and_get_nonces(deposit_outpoint, 1, &operator_takes_sighashes)
            .await?
            .ok_or(BridgeError::NoncesNotFound)?;

        // now iterate over nonces and sighashes and sign the operator_takes_txs
        let operator_takes_partial_sigs = operator_takes_sighashes
            .iter()
            .zip(nonces.iter())
            .map(|(sighash, (sec_nonce, agg_nonce))| {
                musig2::partial_sign(
                    self.config.verifiers_public_keys.clone(),
                    None,
                    *sec_nonce,
                    agg_nonce.clone(),
                    &self.signer.keypair,
                    *sighash,
                )
            })
            .collect::<Vec<_>>();
        Ok(operator_takes_partial_sigs)
    }

    /// verify the operator_take_sigs
    /// sign move_commit_tx and move_reveal_tx
    async fn operator_take_txs_signed(
        &self,
        deposit_outpoint: OutPoint,
        operator_take_sigs: Vec<schnorr::Signature>,
    ) -> Result<MuSigPartialSignature, BridgeError> {
        let (kickoff_utxos, mut move_tx_handler, bridge_fund_outpoint) =
            self.create_deposit_details(deposit_outpoint).await?;

        let _ = kickoff_utxos
            .iter()
            .enumerate()
            .map(|(index, kickoff_utxo)| {
                let (operator_address, _) = TransactionBuilder::create_taproot_address(
                    &[],
                    Some(self.operator_xonly_pks[index]),
                    self.config.network,
                );
                let slash_or_take_tx = TransactionBuilder::create_slash_or_take_tx(
                    deposit_outpoint,
                    kickoff_utxo.clone(),
                    &self.operator_xonly_pks[index],
                    index,
                    &self.nofn_xonly_pk,
                    self.config.network,
                );

                let mut operator_takes_tx = TransactionBuilder::create_operator_takes_tx(
                    bridge_fund_outpoint,
                    OutPoint {
                        txid: slash_or_take_tx.tx.compute_txid(),
                        vout: 0,
                    },
                    slash_or_take_tx.tx.output[0].clone(),
                    &operator_address,
                    &self.nofn_xonly_pk,
                    self.config.network,
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

        let move_tx_sighash =
            Actor::convert_tx_to_sighash_script_spend(&mut move_tx_handler, 0, 0)?; // TODO: This should be musig

        // let move_reveal_sighash =
        //     Actor::convert_tx_to_sighash_script_spend(&mut move_reveal_tx_handler, 0, 0)?; // TODO: This should be musig

        let nonces = self
            .db
            .save_sighashes_and_get_nonces(deposit_outpoint, 0, &[move_tx_sighash.to_byte_array()])
            .await?
            .ok_or(BridgeError::NoncesNotFound)?;

        let move_tx_sig = musig2::partial_sign(
            self.config.verifiers_public_keys.clone(),
            None,
            nonces[0].0,
            nonces[0].1.clone(),
            &self.signer.keypair,
            move_tx_sighash.to_byte_array(),
        );

        // let move_reveal_sig = musig2::partial_sign(
        //     self.config.verifiers_public_keys.clone(),
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
    async fn new_deposit_rpc(
        &self,
        deposit_utxo: OutPoint,
        recovery_taproot_address: Address<NetworkUnchecked>,
        evm_address: EVMAddress,
    ) -> Result<Vec<MuSigPubNonce>, BridgeError> {
        self.new_deposit(deposit_utxo, recovery_taproot_address, evm_address)
            .await
    }

    async fn operator_kickoffs_generated_rpc(
        &self,
        deposit_utxo: OutPoint,
        kickoff_utxos: Vec<UTXO>,
        operators_kickoff_sigs: Vec<schnorr::Signature>,
        agg_nonces: Vec<MuSigAggNonce>,
    ) -> Result<(Vec<MuSigPartialSignature>, Vec<MuSigPartialSignature>), BridgeError> {
        self.operator_kickoffs_generated(
            deposit_utxo,
            kickoff_utxos,
            operators_kickoff_sigs,
            agg_nonces,
        )
        .await
    }

    async fn burn_txs_signed_rpc(
        &self,
        deposit_utxo: OutPoint,
        burn_sigs: Vec<schnorr::Signature>,
        slash_or_take_sigs: Vec<schnorr::Signature>,
    ) -> Result<Vec<MuSigPartialSignature>, BridgeError> {
        self.burn_txs_signed(deposit_utxo, burn_sigs, slash_or_take_sigs)
            .await
    }

    async fn operator_take_txs_signed_rpc(
        &self,
        deposit_utxo: OutPoint,
        operator_take_sigs: Vec<schnorr::Signature>,
    ) -> Result<MuSigPartialSignature, BridgeError> {
        self.operator_take_txs_signed(deposit_utxo, operator_take_sigs)
            .await
    }
}
