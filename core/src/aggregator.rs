use async_trait::async_trait;
use bitcoin::{address::NetworkUnchecked, Address, OutPoint, Transaction};
use secp256k1::schnorr;

use crate::{
    config::BridgeConfig, errors::BridgeError, musig2::{
        aggregate_nonces, AggregateFromPublicKeys, MuSigAggNonce, MuSigPartialSignature,
        MuSigPubNonce,
    }, traits::rpc::AggregatorServer, transaction_builder::TransactionBuilder, utils::{
        aggregate_move_partial_sigs, aggregate_operator_takes_partial_sigs,
        aggregate_slash_or_take_partial_sigs, handle_taproot_witness_new,
    }, EVMAddress, UTXO
};

#[derive(Debug, Clone)]
pub struct Aggregator {
    config: BridgeConfig,
    nofn_xonly_pk: secp256k1::XOnlyPublicKey,
}

impl Aggregator {
    pub async fn new(config: BridgeConfig) -> Result<Self, BridgeError> {
        let nofn_xonly_pk = secp256k1::XOnlyPublicKey::from_musig2_pks(
            config.verifiers_public_keys.clone(),
            None,
            false,
        );

        Ok(Aggregator {
            config,
            nofn_xonly_pk,
        })
    }

    pub async fn aggregate_pub_nonces(
        &self,
        pub_nonces: Vec<Vec<MuSigPubNonce>>,
    ) -> Result<Vec<MuSigAggNonce>, BridgeError> {
        let mut agg_nonces = Vec::new();
        for i in 0..pub_nonces[0].len() {
            let agg_nonce = aggregate_nonces(
                pub_nonces
                    .iter()
                    .map(|v| v.get(i).cloned().unwrap())
                    .collect::<Vec<_>>(),
            );

            agg_nonces.push(agg_nonce);
        }
        Ok(agg_nonces)
    }

    pub async fn aggregate_slash_or_take_sigs(
        &self,
        deposit_outpoint: OutPoint,
        kickoff_utxos: Vec<UTXO>,
        agg_nonces: Vec<MuSigAggNonce>,
        partial_sigs: Vec<Vec<MuSigPartialSignature>>,
    ) -> Result<Vec<schnorr::Signature>, BridgeError> {
        let mut slash_or_take_sigs = Vec::new();
        for i in 0..partial_sigs[0].len() {
            let agg_sig = aggregate_slash_or_take_partial_sigs(
                deposit_outpoint,
                kickoff_utxos[i].clone(),
                self.config.verifiers_public_keys.clone(),
                self.config.operators_xonly_pks[i],
                i,
                &agg_nonces[i + 1 + self.config.operators_xonly_pks.len()].clone(),
                partial_sigs
                    .iter()
                    .map(|v| v.get(i).cloned().unwrap())
                    .collect::<Vec<_>>(),
                self.config.network,
            )?;

            slash_or_take_sigs.push(secp256k1::schnorr::Signature::from_slice(&agg_sig)?);
        }
        Ok(slash_or_take_sigs)
    }

    pub async fn aggregate_operator_take_sigs(
        &self,
        deposit_outpoint: OutPoint,
        kickoff_utxos: Vec<UTXO>,
        agg_nonces: Vec<MuSigAggNonce>,
        partial_sigs: Vec<Vec<MuSigPartialSignature>>,
    ) -> Result<Vec<schnorr::Signature>, BridgeError> {
        let mut operator_take_sigs = Vec::new();
        for i in 0..partial_sigs.len() {
            let agg_sig = aggregate_operator_takes_partial_sigs(
                deposit_outpoint,
                kickoff_utxos[i].clone(),
                &self.config.operators_xonly_pks[i].clone(),
                i,
                self.config.verifiers_public_keys.clone(),
                &agg_nonces[i + 1].clone(),
                partial_sigs.iter().map(|v| v[i]).collect(),
                self.config.network,
            )?;

            operator_take_sigs.push(secp256k1::schnorr::Signature::from_slice(&agg_sig)?);
        }
        Ok(operator_take_sigs)
    }

    pub async fn aggregate_move_tx_sigs(
        &self,
        deposit_outpoint: OutPoint,
        recovery_taproot_address: Address<NetworkUnchecked>,
        evm_address: EVMAddress,
        agg_nonce: MuSigAggNonce,
        partial_sigs: Vec<MuSigPartialSignature>,
    ) -> Result<Transaction, BridgeError> {
        let agg_move_tx_final_sig = aggregate_move_partial_sigs(
            deposit_outpoint,
            &evm_address,
            &recovery_taproot_address,
            self.config.verifiers_public_keys.clone(),
            &agg_nonce,
            partial_sigs,
            self.config.network,
        )?;

        let move_tx_sig = secp256k1::schnorr::Signature::from_slice(&agg_move_tx_final_sig)?;

        let mut move_tx_handler = TransactionBuilder::create_move_tx(
            deposit_outpoint,
            &evm_address,
            &recovery_taproot_address,
            &self.nofn_xonly_pk,
            self.config.network,
        );
        let move_tx_witness_elements = vec![move_tx_sig.serialize().to_vec()];
        handle_taproot_witness_new(&mut move_tx_handler, &move_tx_witness_elements, 0, Some(0))?;

        Ok(move_tx_handler.tx)
    }
}

#[async_trait]
impl AggregatorServer for Aggregator {
    async fn aggregate_pub_nonces_rpc(
        &self,
        pub_nonces: Vec<Vec<MuSigPubNonce>>,
    ) -> Result<Vec<MuSigAggNonce>, BridgeError> {
        self.aggregate_pub_nonces(pub_nonces).await
    }

    async fn aggregate_slash_or_take_sigs_rpc(
        &self,
        deposit_outpoint: OutPoint,
        kickoff_utxos: Vec<UTXO>,
        agg_nonces: Vec<MuSigAggNonce>,
        partial_sigs: Vec<Vec<MuSigPartialSignature>>,
    ) -> Result<Vec<schnorr::Signature>, BridgeError> {
        self.aggregate_slash_or_take_sigs(deposit_outpoint, kickoff_utxos, agg_nonces, partial_sigs)
            .await
    }

    async fn aggregate_operator_take_sigs_rpc(
        &self,
        deposit_outpoint: OutPoint,
        kickoff_utxos: Vec<UTXO>,
        agg_nonces: Vec<MuSigAggNonce>,
        partial_sigs: Vec<Vec<MuSigPartialSignature>>,
    ) -> Result<Vec<schnorr::Signature>, BridgeError> {
        self.aggregate_operator_take_sigs(deposit_outpoint, kickoff_utxos, agg_nonces, partial_sigs)
            .await
    }

    async fn aggregate_move_tx_sigs_rpc(
        &self,
        deposit_outpoint: OutPoint,
        recovery_taproot_address: Address<NetworkUnchecked>,
        evm_address: EVMAddress,
        agg_nonce: MuSigAggNonce,
        partial_sigs: Vec<MuSigPartialSignature>,
    ) -> Result<Transaction, BridgeError> {
        self.aggregate_move_tx_sigs(
            deposit_outpoint,
            recovery_taproot_address,
            evm_address,
            agg_nonce,
            partial_sigs,
        )
        .await
    }
}
