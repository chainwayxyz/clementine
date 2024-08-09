use crate::actor::Actor;
use crate::config::BridgeConfig;
use crate::database::verifier::VerifierDB;
use crate::errors::BridgeError;
use crate::extended_rpc::ExtendedRpc;
use crate::musig2::{self, MuSigAggNonce, MuSigPartialSignature, MuSigPubNonce};
use crate::traits::rpc::VerifierRpcServer;
use crate::transaction_builder::TransactionBuilder;
use crate::{script_builder, utils, EVMAddress, PsbtOutPoint};
use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::Hash;
use bitcoin::sighash::{self};
use bitcoin::{secp256k1, secp256k1::Secp256k1, OutPoint};
use bitcoin::{taproot, Address, Amount, TxOut};
use bitcoin_mock_rpc::RpcApiWrapper;
use clementine_circuits::constants::BRIDGE_AMOUNT_SATS;
use clementine_circuits::sha256_hash;
use jsonrpsee::core::async_trait;
use secp256k1::XOnlyPublicKey;
use secp256k1::{rand, schnorr};
use serde::de;

#[derive(Debug, Clone)]
pub struct Verifier<R>
where
    R: RpcApiWrapper,
{
    rpc: ExtendedRpc<R>,
    signer: Actor,
    db: VerifierDB,
    config: BridgeConfig,
}

impl<R> Verifier<R>
where
    R: RpcApiWrapper,
{
    pub async fn new(rpc: ExtendedRpc<R>, config: BridgeConfig) -> Result<Self, BridgeError> {
        let signer = Actor::new(config.secret_key, config.network);

        let secp: Secp256k1<secp256k1::All> = Secp256k1::new();

        let pk: secp256k1::PublicKey = config.secret_key.public_key(&secp);
        // let xonly_pk = XOnlyPublicKey::from(pk);

        // Generated public key must be in given public key list.
        if !config.verifiers_public_keys.contains(&pk) {
            return Err(BridgeError::PublicKeyNotFound);
        }

        let db = VerifierDB::new(config.clone()).await;

        Ok(Verifier {
            rpc,
            signer,
            db,
            config,
        })
    }

    /// Operator only endpoint for verifier.
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
            &self.config.verifiers_public_keys,
            &deposit_utxo,
            recovery_taproot_address,
            evm_address,
            BRIDGE_AMOUNT_SATS,
            self.config.user_takes_after,
            self.config.confirmation_treshold,
        )?;

        let num_required_sigs = 10; // TODO: Fix this

        let pub_nonces_from_db = self.db.get_pub_nonces(deposit_utxo).await?;
        if let Some(pub_nonces) = pub_nonces_from_db {
            return Ok(pub_nonces);
        }

        // let nonces = musig::nonce_pair(&self.signer.keypair);
        // TODO: Either find a way to put the pks here, or remove the pks
        // from the nonce_pair, proceed with directly giving the index
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
        operators_kickoff_sigs: Vec<secp256k1::schnorr::Signature>,
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
                &self.signer.xonly_public_key, // TOOD: Fix this to correct operator
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

        let nonces = futures::future::try_join_all(future_nonces)
            .await?
            .into_iter()
            .map(|opt| opt.ok_or(BridgeError::NoncesNotFound))
            .collect::<Result<Vec<_>, _>>()?;

        let operator_takes_partial_sigs = kickoff_outpoints_and_amounts
            .iter()
            .enumerate()
            .map(|(index, (kickoff_outpoint, kickoff_amount))| {
                let ins = TransactionBuilder::create_tx_ins(vec![kickoff_outpoint.clone()]);
                let outs = vec![
                    TxOut {
                        value: Amount::from_sat(kickoff_amount.to_sat() - 330),
                        script_pubkey: self.signer.address.script_pubkey(), // TODO: Fix this address to operator or 200 blocks N-of-N
                    },
                    script_builder::anyone_can_spend_txout(),
                ];
                let tx = TransactionBuilder::create_btc_tx(ins, outs);

                let ins = TransactionBuilder::create_tx_ins(vec![
                    deposit_utxo.clone(),
                    OutPoint {
                        txid: tx.compute_txid(),
                        vout: 0,
                    },
                ]);
                let outs = vec![
                    TxOut {
                        value: Amount::from_sat(
                            kickoff_amount.to_sat() - 330 + BRIDGE_AMOUNT_SATS - 330,
                        ),
                        script_pubkey: self.signer.address.script_pubkey(), // TODO: Fix this address to operator
                    },
                    script_builder::anyone_can_spend_txout(),
                ];

                let tx = TransactionBuilder::create_btc_tx(ins, outs);

                let bridge_txout = TxOut {
                    value: Amount::from_sat(BRIDGE_AMOUNT_SATS - 200 - 330), // TODO: Fix min relay fee, not 200
                    script_pubkey: self.signer.address.script_pubkey(), // TODO: Fix this to N-of-N
                };
                let kickoff_txout = TxOut {
                    value: *kickoff_amount,
                    script_pubkey: self.signer.address.script_pubkey(), // TODO: Fix this address to operator or 200 blocks N-of-N
                };

                let prevouts = vec![bridge_txout, kickoff_txout];

                let musig_script =
                    script_builder::generate_script_n_of_n(&vec![self.signer.xonly_public_key]); // TODO: Fix this to N-of-N musig

                let mut sighash_cache = sighash::SighashCache::new(tx);
                let sig_hash = sighash_cache
                    .taproot_script_spend_signature_hash(
                        0,
                        &bitcoin::sighash::Prevouts::All(&prevouts),
                        bitcoin::TapLeafHash::from_script(
                            &musig_script,
                            taproot::LeafVersion::TapScript,
                        ),
                        sighash::TapSighashType::Default,
                    )
                    .unwrap(); // Is unwrap safe here?

                let operator_takes_partial_sig = musig2::partial_sign(
                    vec![],
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

        kickoff_outpoints_and_amounts.iter().enumerate().map(
            |(index, (kickoff_outpoint, kickoff_amount))| {
                let ins = TransactionBuilder::create_tx_ins(vec![kickoff_outpoint.clone()]);
                let outs = vec![
                    TxOut {
                        value: Amount::from_sat(kickoff_amount.to_sat() - 330),
                        script_pubkey: self.signer.address.script_pubkey(), // TODO: Fix this address to operator or 200 blocks N-of-N
                    },
                    script_builder::anyone_can_spend_txout(),
                ];
                let tx = TransactionBuilder::create_btc_tx(ins, outs);

                let ins = TransactionBuilder::create_tx_ins(vec![
                    deposit_utxo.clone(),
                    OutPoint {
                        txid: tx.compute_txid(),
                        vout: 0,
                    },
                ]);
                let outs = vec![
                    TxOut {
                        value: Amount::from_sat(
                            kickoff_amount.to_sat() - 330 + BRIDGE_AMOUNT_SATS - 330,
                        ),
                        script_pubkey: self.signer.address.script_pubkey(), // TODO: Fix this address to operator
                    },
                    script_builder::anyone_can_spend_txout(),
                ];

                let tx = TransactionBuilder::create_btc_tx(ins, outs);

                let bridge_txout = TxOut {
                    value: Amount::from_sat(BRIDGE_AMOUNT_SATS - 200 - 330), // TODO: Fix min relay fee, not 200
                    script_pubkey: self.signer.address.script_pubkey(), // TODO: Fix this to N-of-N
                };
                let kickoff_txout = TxOut {
                    value: *kickoff_amount,
                    script_pubkey: self.signer.address.script_pubkey(), // TODO: Fix this address to operator or 200 blocks N-of-N
                };

                let prevouts = vec![bridge_txout, kickoff_txout];

                let musig_script =
                    script_builder::generate_script_n_of_n(&vec![self.signer.xonly_public_key]); // TODO: Fix this to N-of-N musig

                let mut sighash_cache = sighash::SighashCache::new(tx);
                let sig_hash = sighash_cache
                    .taproot_script_spend_signature_hash(
                        0,
                        &bitcoin::sighash::Prevouts::All(&prevouts),
                        bitcoin::TapLeafHash::from_script(
                            &musig_script,
                            taproot::LeafVersion::TapScript,
                        ),
                        sighash::TapSighashType::Default,
                    )
                    .unwrap(); // Is unwrap safe here?

                // verify tjhe operator_take_sigs
                utils::SECP
                    .verify_schnorr(
                        &operator_take_sigs[index],
                        &secp256k1::Message::from_digest(sig_hash.to_byte_array()),
                        &self.signer.xonly_public_key, // TOOD: Fix this to N-of-N pubkey
                    )
                    .unwrap();
            },
        );

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
            &self.config.verifiers_public_keys,
            &kickoff_utxos,
            201, // TODO: Fix this
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
            &self.config.verifiers_public_keys,
            &kickoff_utxos,
            201, // TODO: Fix this
        );

        let move_reveal_sig =
            self.signer
                .sighash_taproot_script_spend(&mut move_reveal_tx, 0, 0)?; // TODO: This should be musig

        Ok((
            move_commit_sig.to_byte_array() as MusigPartialSignature,
            move_reveal_sig.to_byte_array() as MusigPartialSignature,
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
