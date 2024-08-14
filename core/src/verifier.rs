use crate::actor::Actor;
use crate::config::BridgeConfig;
use crate::database::verifier::VerifierDB;
use crate::errors::BridgeError;
use crate::extended_rpc::ExtendedRpc;
use crate::musig2::{self, MuSigAggNonce, MuSigPartialSignature, MuSigPubNonce};
use crate::traits::rpc::VerifierRpcServer;
use crate::transaction_builder::{
    TransactionBuilder, MOVE_COMMIT_TX_MIN_RELAY_FEE, MOVE_REVEAL_TX_MIN_RELAY_FEE,
};
use crate::{script_builder, utils, EVMAddress, PsbtOutPoint};
use ::musig2::secp::Point;
use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::Hash;
use bitcoin::sighash::{self};
use bitcoin::{secp256k1, OutPoint};
use bitcoin::{taproot, Address, Amount, TxOut};
use bitcoin_mock_rpc::RpcApiWrapper;
use clementine_circuits::constants::BRIDGE_AMOUNT_SATS;
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
    async fn new_deposit(
        &self,
        deposit_utxo: &OutPoint,
        recovery_taproot_address: &Address<NetworkUnchecked>,
        evm_address: &EVMAddress,
    ) -> Result<Vec<MuSigPubNonce>, BridgeError> {
        self.rpc.check_deposit_utxo(
            &self.nofn_xonly_pk,
            &deposit_utxo,
            recovery_taproot_address,
            evm_address,
            BRIDGE_AMOUNT_SATS,
            self.config.user_takes_after,
            self.config.confirmation_treshold,
            self.config.network,
        )?;

        let num_required_sigs = 10; // TODO: Fix this: move_commit and move_reveal tx signatures + operator_take_txs signatures for every operator

        // Check if we already have pub_nonces for this deposit_utxo.
        let pub_nonces_from_db = self.db.get_pub_nonces(deposit_utxo).await?;
        if let Some(pub_nonces) = pub_nonces_from_db {
            return Ok(pub_nonces);
        }

        let nonces = (0..num_required_sigs)
            .map(|_| musig2::nonce_pair(&self.signer.keypair, &mut rand::rngs::OsRng))
            .collect::<Vec<_>>();

        let transaction = self.db.begin_transaction().await?;
        self.db
            .save_deposit_info(deposit_utxo, recovery_taproot_address, evm_address)
            .await?;
        self.db.save_nonces(deposit_utxo, &nonces).await?;
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
    /// - for every kickoff_utxo, calculate kickoff2_tx
    /// - for every kickoff2_tx, partial sign burn_tx (ommitted for now)
    /// - return MuSigPartialSignature of sign(kickoff2_txids)
    async fn operator_kickoffs_generated(
        &self,
        deposit_utxo: &OutPoint,
        kickoff_utxos: Vec<PsbtOutPoint>,
        operators_kickoff_sigs: Vec<secp256k1::schnorr::Signature>, // These are not transaction signatures, rather, they are to verify the operator's identity.
        agg_nonces: Vec<MuSigAggNonce>,
    ) -> Result<Vec<MuSigPartialSignature>, BridgeError> {
        if operators_kickoff_sigs.len() != kickoff_utxos.len() {
            return Err(BridgeError::InvalidKickoffUtxo);
        }

        for (i, kickoff_utxo) in kickoff_utxos.iter().enumerate() {
            let value = kickoff_utxo.tx.output[kickoff_utxo.vout as usize].value;
            if value.to_sat() < 100_000 {
                return Err(BridgeError::InvalidKickoffUtxo);
            }

            let kickoff_sig_hash = sha256_hash!(
                deposit_utxo.txid,
                deposit_utxo.vout.to_be_bytes(),
                kickoff_utxo.tx.compute_txid(),
                kickoff_utxo.vout.to_be_bytes()
            );

            utils::SECP.verify_schnorr(
                &operators_kickoff_sigs[i],
                &secp256k1::Message::from_digest(kickoff_sig_hash),
                &self.signer.xonly_public_key, // TODO: Fix this to correct operator
            )?;
        }

        let kickoff_outpoints_and_amounts = kickoff_utxos
            .iter()
            .map(|x| {
                (
                    OutPoint {
                        txid: x.tx.compute_txid(),
                        vout: x.vout,
                    },
                    x.tx.output[x.vout as usize].value,
                )
            })
            .collect::<Vec<_>>();

        self.db.save_agg_nonces(deposit_utxo, &agg_nonces).await?;

        self.db
            .save_kickoff_outpoints_and_amounts(deposit_utxo, &kickoff_outpoints_and_amounts)
            .await?;

        // TODO: Sign burn txs
        Ok(vec![])
    }

    /// verify burn txs are signed by verifiers
    /// sign operator_takes_txs
    async fn burn_txs_signed_rpc(
        &self,
        deposit_utxo: &OutPoint,
        _burn_sigs: Vec<schnorr::Signature>,
    ) -> Result<Vec<MuSigPartialSignature>, BridgeError> {
        // TODO: Verify burn txs are signed by verifiers

        let kickoff_outpoints_and_amounts = self
            .db
            .get_kickoff_outpoints_and_amounts(deposit_utxo)
            .await?;

        let kickoff_outpoints_and_amounts =
            kickoff_outpoints_and_amounts.ok_or(BridgeError::KickoffOutpointsNotFound)?;

        let future_nonces = (0..kickoff_outpoints_and_amounts.len())
            .map(|i| self.db.get_nonces(&deposit_utxo, i + 2)); // i + 2 is bcs we used the first two nonce for move_txs
        let bridge_fund_txid = self.db.get_bridge_fund_txid(*deposit_utxo).await?;
        let bridge_fund_utxo = OutPoint {
            txid: bridge_fund_txid,
            vout: 0,
        };

        let nonces = futures::future::try_join_all(future_nonces)
            .await?
            .into_iter()
            .map(|opt| opt.ok_or(BridgeError::NoncesNotFound))
            .collect::<Result<Vec<_>, _>>()?;

        let operator_takes_partial_sigs = kickoff_outpoints_and_amounts
            .iter()
            .enumerate()
            .map(|(index, (kickoff_outpoint, kickoff_amount))| {
                let (operator_address, _) = TransactionBuilder::create_taproot_address(
                    &[],
                    Some(self.operator_xonly_pks[index]),
                    self.config.network.clone(),
                );
                let slash_or_take_tx = TransactionBuilder::create_slash_or_take_tx(
                    kickoff_outpoint.clone(),
                    TxOut {
                        value: *kickoff_amount,
                        script_pubkey: operator_address.script_pubkey(),
                    },
                    &self.operator_xonly_pks[index],
                    &self.nofn_xonly_pk,
                    self.config.network,
                );

                let mut operator_takes_tx = TransactionBuilder::create_operator_takes_tx(
                    bridge_fund_utxo.clone(),
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
                let operator_takes_partial_sig = musig2::partial_sign(
                    vec![], // TODO Fix this
                    None,
                    nonces[index].1,
                    nonces[index].2.clone(),
                    &self.signer.keypair,
                    sig_hash.to_byte_array(),
                );
                operator_takes_partial_sig as MuSigPartialSignature
            })
            .collect::<Vec<_>>();

        Ok(operator_takes_partial_sigs)
    }

    /// verify the operator_take_sigs
    /// sign move_commit_tx and move_reveal_tx
    async fn operator_take_txs_signed_rpc(
        &self,
        deposit_utxo: &OutPoint,
        operator_take_sigs: Vec<schnorr::Signature>,
    ) -> Result<(MuSigPartialSignature, MuSigPartialSignature), BridgeError> {
        let kickoff_outpoints_and_amounts = self
            .db
            .get_kickoff_outpoints_and_amounts(deposit_utxo)
            .await?;

        let kickoff_outpoints_and_amounts =
            kickoff_outpoints_and_amounts.ok_or(BridgeError::KickoffOutpointsNotFound)?;

        let bridge_fund_txid = self.db.get_bridge_fund_txid(*deposit_utxo).await?;
        let bridge_fund_utxo = OutPoint {
            txid: bridge_fund_txid,
            vout: 0,
        };

        let verification_result = kickoff_outpoints_and_amounts.iter().enumerate().map(
            |(index, (kickoff_outpoint, kickoff_amount))| {
                let (operator_address, _) = TransactionBuilder::create_taproot_address(
                    &[],
                    Some(self.operator_xonly_pks[index]),
                    self.config.network.clone(),
                );
                let slash_or_take_tx = TransactionBuilder::create_slash_or_take_tx(
                    kickoff_outpoint.clone(),
                    TxOut {
                        value: *kickoff_amount,
                        script_pubkey: operator_address.script_pubkey(),
                    },
                    &self.operator_xonly_pks[index],
                    &self.nofn_xonly_pk,
                    self.config.network,
                );

                let mut operator_takes_tx = TransactionBuilder::create_operator_takes_tx(
                    bridge_fund_utxo.clone(),
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
            },
        );
        println!("Verification result: {:?}", verification_result);

        let (recovery_taproot_address, evm_address) = self
            .db
            .get_deposit_info(deposit_utxo)
            .await?
            .ok_or(BridgeError::DepositInfoNotFound)?;

        let kickoff_utxos = kickoff_outpoints_and_amounts
            .iter()
            .map(|(outpoint, _)| outpoint.clone())
            .collect::<Vec<_>>();

        let mut move_commit_tx = TransactionBuilder::create_move_commit_tx(
            *deposit_utxo,
            &evm_address,
            &recovery_taproot_address,
            200, // TODO: Fix this
            &self.nofn_xonly_pk,
            &kickoff_utxos,
            201, // TODO: Fix this
            self.config.network.clone(),
        );

        let move_commit_sig =
            self.signer
                .sighash_taproot_script_spend(&mut move_commit_tx, 0, 0)?; // TODO: This should be musig

        let mut move_reveal_tx = TransactionBuilder::create_move_reveal_tx(
            OutPoint {
                txid: move_commit_tx.tx.compute_txid(),
                vout: 0,
            },
            &evm_address,
            &recovery_taproot_address,
            &self.nofn_xonly_pk,
            &kickoff_utxos,
            201, // TODO: Fix this
            self.config.network.clone(),
        );

        let move_reveal_sig =
            self.signer
                .sighash_taproot_script_spend(&mut move_reveal_tx, 0, 0)?; // TODO: This should be musig

        Ok((
            move_commit_sig.to_byte_array() as MuSigPartialSignature,
            move_reveal_sig.to_byte_array() as MuSigPartialSignature,
        ))
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
        self.new_deposit(&deposit_utxo, &recovery_taproot_address, &evm_address)
            .await
    }

    async fn operator_kickoffs_generated_rpc(
        &self,
        deposit_utxo: OutPoint,
        kickoff_utxos: Vec<PsbtOutPoint>,
        operators_kickoff_sigs: Vec<schnorr::Signature>,
        agg_nonces: Vec<MuSigAggNonce>,
    ) -> Result<Vec<MuSigPartialSignature>, BridgeError> {
        self.operator_kickoffs_generated(
            &deposit_utxo,
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
    ) -> Result<Vec<MuSigPartialSignature>, BridgeError> {
        self.burn_txs_signed_rpc(&deposit_utxo, burn_sigs).await
    }

    async fn operator_take_txs_signed_rpc(
        &self,
        deposit_utxo: OutPoint,
        operator_take_sigs: Vec<schnorr::Signature>,
    ) -> Result<(MuSigPartialSignature, MuSigPartialSignature), BridgeError> {
        self.operator_take_txs_signed_rpc(&deposit_utxo, operator_take_sigs)
            .await
    }
}
