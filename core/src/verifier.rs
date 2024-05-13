use crate::config::BridgeConfig;
#[cfg(feature = "poc")]
use crate::constants::CONNECTOR_TREE_DEPTH;
use crate::db::verifier::VerifierDB;
use crate::errors::BridgeError;
use crate::extended_rpc::ExtendedRpc;
use crate::operator::{AggNonces, DepositPubNonces};
use crate::script_builder::ScriptBuilder;
use crate::traits::rpc::VerifierRpcServer;
// use crate::traits::verifier::VerifierConnector;
use crate::transaction_builder::TransactionBuilder;
use crate::utils::check_deposit_utxo;
use crate::{actor::Actor, operator::DepositPresigns};
use crate::{ByteArray66, EVMAddress};
use bitcoin::address::{NetworkChecked, NetworkUnchecked};
use bitcoin::{secp256k1, secp256k1::Secp256k1, OutPoint};
use bitcoin::{Address, Amount, TxOut};
use clementine_circuits::constants::BRIDGE_AMOUNT_SATS;
use jsonrpsee::core::async_trait;
use musig2::{AggNonce, FirstRound, KeyAggContext, PartialSignature, SecNonceSpices};
use secp256k1::{schnorr, SecretKey};
use secp256k1::{Keypair, PublicKey, XOnlyPublicKey};

#[derive(Debug, Clone)]
pub struct Verifier {
    pub rpc: ExtendedRpc,
    pub secp: Secp256k1<secp256k1::All>,
    pub signer: Actor,
    pub transaction_builder: TransactionBuilder,
    pub verifiers_xonly_pks: Vec<XOnlyPublicKey>,
    pub verifiers_pks: Vec<PublicKey>,
    pub operator_pk: XOnlyPublicKey,
    pub agg_pk: PublicKey,
    pub db: VerifierDB,
    pub idx: usize,
    config: BridgeConfig,
    sec_nonce: [u8; 32],
}

#[async_trait]
impl VerifierRpcServer for Verifier {
    async fn new_deposit_first_round_rpc(
        &self,
        start_utxo: OutPoint,
        recovery_taproot_address: Address<NetworkUnchecked>,
        evm_address: EVMAddress,
        operator_address: Address<NetworkUnchecked>,
    ) -> Result<DepositPubNonces, BridgeError> {
        let operator_address = operator_address.require_network(self.config.network)?;
        self.new_deposit_first_round(
            start_utxo,
            &recovery_taproot_address,
            &evm_address,
            &operator_address,
        )
        .await
    }
    async fn new_deposit_second_round_rpc(
        &self,
        start_utxo: OutPoint,
        recovery_taproot_address: Address<NetworkUnchecked>,
        evm_address: EVMAddress,
        operator_address: Address<NetworkUnchecked>,
        aggregated_nonces: AggNonces,
    ) -> Result<DepositPresigns, BridgeError> {
        let _operator_address = operator_address.require_network(self.config.network)?;
        self.new_deposit_second_round(
            start_utxo,
            &recovery_taproot_address,
            &evm_address,
            &aggregated_nonces,
        )
        .await
    }
    async fn new_withdrawal_first_round_rpc(
        &self,
        withdrawal_idx: usize,
        withdrawal_address: Address<NetworkUnchecked>,
    ) -> Result<ByteArray66, BridgeError> {
        let withdrawal_address = withdrawal_address.require_network(self.config.network)?;
        self.new_withdrawal_first_round(withdrawal_idx, &withdrawal_address)
            .await
    }
    async fn new_withdrawal_second_round_rpc(
        &self,
        withdrawal_idx: usize,
        withdrawal_address: Address<NetworkUnchecked>,
        aggregated_nonce: ByteArray66,
    ) -> Result<[u8; 32], BridgeError> {
        let withdrawal_address = withdrawal_address.require_network(self.config.network)?;
        self.new_withdrawal_second_round(withdrawal_idx, &withdrawal_address, &aggregated_nonce)
            .await
    }
}

impl Verifier {
    /// this is a endpoint that only the operator can call
    /// 1. Check if the deposit utxo is valid and finalized (6 blocks confirmation)
    /// 2. Check if the utxo is not already spent
    /// 3. Give move signature and operator claim signatures
    async fn new_deposit_first_round(
        &self,
        start_utxo: OutPoint,
        recovery_taproot_address: &Address<NetworkUnchecked>,
        evm_address: &EVMAddress,
        _operator_address: &Address,
    ) -> Result<DepositPubNonces, BridgeError> {
        check_deposit_utxo(
            &self.rpc,
            &self.transaction_builder,
            &start_utxo,
            recovery_taproot_address,
            evm_address,
            BRIDGE_AMOUNT_SATS,
            self.config.confirmation_treshold,
        )?;

        let deposit_index = self.db.get_next_deposit_index().await?;
        tracing::debug!("VERIFIER deposit_index: {:?}", deposit_index);

        let mut move_tx = self.transaction_builder.create_move_tx(
            start_utxo,
            evm_address,
            &recovery_taproot_address,
        )?;

        let move_tx_sighash = Actor::convert_tx_to_sighash(&mut move_tx, 0, 0)?;
        tracing::debug!("Verifier move_tx_sighash: {:?}", move_tx_sighash);

        let key_agg_ctx = KeyAggContext::new(self.verifiers_pks.clone()).unwrap();
        // let agg_pk: PublicKey = key_agg_ctx.aggregated_pubkey();

        let move_tx_first_round = FirstRound::new(
            key_agg_ctx.clone(),
            self.sec_nonce,
            self.idx,
            SecNonceSpices::new()
                .with_seckey(self.signer.secret_key.clone())
                .with_message(&move_tx_sighash),
        )
        .unwrap();
        let our_pub_nonce = move_tx_first_round.our_public_nonce();
        let move_pub_nonce = ByteArray66(our_pub_nonce.serialize());

        let op_claim_pub_nonces: Vec<ByteArray66> = Vec::new();

        Ok(DepositPubNonces {
            move_pub_nonce: move_pub_nonce,
            op_claim_pub_nonce_vec: op_claim_pub_nonces,
        })
    }

    async fn new_deposit_second_round(
        &self,
        start_utxo: OutPoint,
        recovery_taproot_address: &Address<NetworkUnchecked>,
        evm_address: &EVMAddress,
        aggregated_nonces: &AggNonces,
    ) -> Result<DepositPresigns, BridgeError> {
        tracing::debug!("Verifier is signing move_tx...");
        tracing::debug!("Aggregated nonces: {:?}", aggregated_nonces);
        self.db
            .add_deposit_transaction(start_utxo, recovery_taproot_address.clone(), *evm_address)
            .await?;
        let transaction = self.db.begin_transaction().await?;
        let mut move_tx = self.transaction_builder.create_move_tx(
            start_utxo,
            evm_address,
            &recovery_taproot_address,
        )?;

        // Recreate the FirstRound of MuSig2 for move_tx to generate a partial signature
        let move_tx_sighash = Actor::convert_tx_to_sighash(&mut move_tx, 0, 0)?;
        let sec_nonce = self.sec_nonce;
        let key_agg_ctx = KeyAggContext::new(self.verifiers_pks.clone()).unwrap();
        let move_tx_first_round = FirstRound::new(
            key_agg_ctx,
            sec_nonce,
            self.idx,
            SecNonceSpices::new()
                .with_seckey(self.signer.secret_key.clone())
                .with_message(&move_tx_sighash),
        )
        .unwrap();

        let move_agg_nonce = hex::encode(aggregated_nonces.move_agg_nonce.0)
            .parse::<AggNonce>()
            .unwrap();

        let move_sig: PartialSignature = move_tx_first_round
            .sign_for_aggregator(self.signer.secret_key, move_tx_sighash, &move_agg_nonce)
            .unwrap();
        tracing::debug!("Verifier move_sig: {:?}", move_sig);

        let op_claim_sigs = Vec::new();

        self.db.insert_move_txid(move_tx.tx.txid()).await?;

        if let Err(e) = transaction.commit().await {
            return Err(BridgeError::DatabaseError(e));
        };

        Ok(DepositPresigns {
            move_sign: move_sig.serialize(),
            operator_claim_sign: op_claim_sigs,
        })
    }

    async fn new_withdrawal_first_round(
        &self,
        withdrawal_idx: usize,
        withdrawal_address: &Address<NetworkChecked>,
    ) -> Result<ByteArray66, BridgeError> {
        // TODO: Check from citrea rpc if the withdrawal is valid
        let bridge_txid = self.db.get_deposit_tx(withdrawal_idx).await?;
        tracing::debug!(
            "VERIFIER FIRST round is signing withdrawal_tx with bridge_txid: {:?}",
            bridge_txid
        );
        let bridge_utxo = OutPoint {
            txid: bridge_txid,
            vout: 0,
        };

        let (bridge_address, _) = self.transaction_builder.generate_musig2_bridge_address()?;
        let dust_value = ScriptBuilder::anyone_can_spend_txout().value;
        let bridge_txout = TxOut {
            value: Amount::from_sat(BRIDGE_AMOUNT_SATS - self.config.min_relay_fee) - dust_value,
            script_pubkey: bridge_address.script_pubkey(),
        };

        let mut withdrawal_tx = self.transaction_builder.create_withdraw_tx(
            bridge_utxo,
            bridge_txout,
            withdrawal_address,
        )?;
        tracing::debug!(
            "VERIFIER FIRST round withdrawal_txid: {:?}",
            withdrawal_tx.tx.txid()
        );
        let withdrawal_tx_sighash = Actor::convert_tx_to_sighash(&mut withdrawal_tx, 0, 0)?;
        let key_agg_ctx = KeyAggContext::new(self.verifiers_pks.clone()).unwrap();
        // let agg_pk: PublicKey = key_agg_ctx.aggregated_pubkey();
        let withdrawal_tx_first_round = FirstRound::new(
            key_agg_ctx,
            self.sec_nonce,
            self.idx,
            SecNonceSpices::new()
                .with_seckey(self.signer.secret_key.clone())
                .with_message(&withdrawal_tx_sighash),
        )
        .unwrap();
        let our_pub_nonce = withdrawal_tx_first_round.our_public_nonce();
        let withdrawal_pub_nonce = ByteArray66(our_pub_nonce.serialize());
        Ok(withdrawal_pub_nonce)
    }

    async fn new_withdrawal_second_round(
        &self,
        withdrawal_idx: usize,
        withdrawal_address: &Address<NetworkChecked>,
        aggregated_nonce: &ByteArray66,
    ) -> Result<[u8; 32], BridgeError> {
        let bridge_txid = self.db.get_deposit_tx(withdrawal_idx).await?;
        tracing::debug!(
            "VERIFIER SECOND round is signing withdrawal_tx with bridge_txid: {:?}",
            bridge_txid
        );
        let bridge_utxo = OutPoint {
            txid: bridge_txid,
            vout: 0,
        };

        let (bridge_address, _) = self.transaction_builder.generate_musig2_bridge_address()?;
        let dust_value = ScriptBuilder::anyone_can_spend_txout().value;
        let bridge_txout = TxOut {
            value: Amount::from_sat(BRIDGE_AMOUNT_SATS - self.config.min_relay_fee) - dust_value,
            script_pubkey: bridge_address.script_pubkey(),
        };

        let mut withdrawal_tx = self.transaction_builder.create_withdraw_tx(
            bridge_utxo,
            bridge_txout,
            withdrawal_address,
        )?;
        tracing::debug!("VERIFIER withdrawal_tx: {:?}", withdrawal_tx);
        tracing::debug!(
            "VERIFIER SECOND round withdrawal_txid: {:?}",
            withdrawal_tx.tx.txid()
        );
        let withdrawal_tx_sighash = Actor::convert_tx_to_sighash(&mut withdrawal_tx, 0, 0)?;
        let key_agg_ctx = KeyAggContext::new(self.verifiers_pks.clone()).unwrap();
        // let agg_pk: PublicKey = key_agg_ctx.aggregated_pubkey();
        let withdrawal_tx_first_round = FirstRound::new(
            key_agg_ctx,
            self.sec_nonce,
            self.idx,
            SecNonceSpices::new()
                .with_seckey(self.signer.secret_key.clone())
                .with_message(&withdrawal_tx_sighash),
        )
        .unwrap();
        let move_agg_nonce = hex::encode(aggregated_nonce.0).parse::<AggNonce>().unwrap();
        tracing::debug!("VERIFIER aggregated nonce: {:?}", move_agg_nonce);
        let withdrawal_sig: PartialSignature = withdrawal_tx_first_round
            .sign_for_aggregator(
                self.signer.secret_key,
                withdrawal_tx_sighash,
                &move_agg_nonce,
            )
            .unwrap();
        Ok(withdrawal_sig.serialize())
    }

    #[cfg(feature = "poc")]
    /// TODO: Add verification for the connector tree hashes
    fn connector_roots_created(
        &self,
        connector_tree_hashes: &Vec<HashTree>,
        first_source_utxo: &OutPoint,
        start_blockheight: u64,
        period_relative_block_heights: Vec<u32>,
    ) -> Result<(), BridgeError> {
        let (_claim_proof_merkle_roots, _, _utxo_trees, _claim_proof_merkle_trees) =
            self.transaction_builder.create_all_connector_trees(
                &connector_tree_hashes,
                &first_source_utxo,
                start_blockheight,
                &period_relative_block_heights,
            )?;

        // self.db
        //     .set_connector_tree_utxos(utxo_trees);
        // self.db
        //     .set_connector_tree_hashes(connector_tree_hashes.clone());
        // self.db
        //     .set_claim_proof_merkle_trees(claim_proof_merkle_trees);
        // self.db
        //     .set_start_block_height(start_blockheight);
        // self.db
        //     .set_period_relative_block_heights(period_relative_block_heights);

        Ok(())
    }

    #[cfg(feature = "poc")]
    /// Challenges the operator for current period for now
    /// Will return the blockhash, total work, and period
    fn challenge_operator(&self, period: u8) -> Result<VerifierChallenge, BridgeError> {
        tracing::info!("Verifier starts challenges");
        let last_blockheight = self.rpc.get_block_count()?;
        let last_blockhash = self.rpc.get_block_hash(
            self.db.get_start_block_height()
                + self.db.get_period_relative_block_heights()[period as usize] as u64
                - 1,
        )?;
        tracing::debug!("Verifier last_blockhash: {:?}", last_blockhash);
        let total_work = self.rpc.calculate_total_work_between_blocks(
            self.db.get_start_block_height(),
            last_blockheight,
        )?;
        Ok((last_blockhash, total_work, period))
    }
}

impl Verifier {
    pub async fn new(
        rpc: ExtendedRpc,
        all_xonly_pks: Vec<XOnlyPublicKey>,
        all_pks: Vec<PublicKey>,
        sk: SecretKey,
        config: BridgeConfig,
    ) -> Result<Self, BridgeError> {
        let signer = Actor::new(sk, config.network);
        let secp: Secp256k1<secp256k1::All> = Secp256k1::new();

        let pk: secp256k1::PublicKey = sk.public_key(&secp);
        let xonly_pk = XOnlyPublicKey::from(pk);
        // if pk is not in all_pks, we should raise an error
        if !all_xonly_pks.contains(&xonly_pk) {
            return Err(BridgeError::PublicKeyNotFound);
        }

        let sec_nonce: [u8; 32] = [0u8; 32];

        let key_agg_ctx = KeyAggContext::new(all_pks.clone()).unwrap();
        let agg_pk: PublicKey = key_agg_ctx.aggregated_pubkey();

        let transaction_builder =
            TransactionBuilder::new(all_xonly_pks.clone(), agg_pk, config.clone());
        let operator_pk = all_xonly_pks[all_xonly_pks.len() - 1];
        let idx = all_xonly_pks
            .iter()
            .position(|xonly_pk| {
                *xonly_pk
                    == XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(
                        &secp,
                        &config.secret_key,
                    ))
                    .0
            })
            .unwrap();
        let db = VerifierDB::new(config.clone()).await;
        Ok(Verifier {
            rpc,
            secp,
            signer,
            transaction_builder,
            verifiers_xonly_pks: all_xonly_pks,
            verifiers_pks: all_pks,
            operator_pk,
            agg_pk,
            idx,
            db,
            config,
            sec_nonce,
        })
    }
}
