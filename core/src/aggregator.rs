use crate::{
    actor::Actor,
    config::BridgeConfig,
    errors::BridgeError,
    musig2::{
        aggregate_nonces, aggregate_partial_signatures, AggregateFromPublicKeys, MuSigAggNonce,
        MuSigPartialSignature, MuSigPubNonce,
    },
    traits::rpc::AggregatorServer,
    transaction_builder::TransactionBuilder,
    utils::{self, handle_taproot_witness_new},
    EVMAddress, UTXO,
};
use async_trait::async_trait;
use bitcoin::hashes::Hash;
use bitcoin::{address::NetworkUnchecked, Address, OutPoint, Transaction};
use bitcoincore_rpc::RawTx;
use secp256k1::schnorr;

/// Aggregator struct.
/// This struct is responsible for aggregating partial signatures from the verifiers.
/// It will have in total 3 * num_operator + 1 aggregated nonces.
/// [0] -> Aggregated nonce for the move transaction.
/// [1..num_operator + 1] -> Aggregated nonces for the operator_takes transactions.
/// [num_operator + 1..2 * num_operator + 1] -> Aggregated nonces for the slash_or_take transactions.
/// [2 * num_operator + 1..3 * num_operator + 1] -> Aggregated nonces for the burn transactions.
/// For now, we do not have the last bit.
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

    fn aggregate_slash_or_take_partial_sigs(
        &self,
        deposit_outpoint: OutPoint,
        kickoff_utxo: UTXO,
        operator_xonly_pk: secp256k1::XOnlyPublicKey,
        operator_idx: usize,
        agg_nonce: &MuSigAggNonce,
        partial_sigs: Vec<[u8; 32]>,
    ) -> Result<[u8; 64], BridgeError> {
        let musig_agg_xonly_pubkey_wrapped = secp256k1::XOnlyPublicKey::from_musig2_pks(
            self.config.verifiers_public_keys.clone(),
            None,
            false,
        );
        let mut tx = TransactionBuilder::create_slash_or_take_tx(
            deposit_outpoint,
            kickoff_utxo,
            &operator_xonly_pk,
            operator_idx,
            &musig_agg_xonly_pubkey_wrapped,
            self.config.network,
        );
        tracing::debug!("SLASH_OR_TAKE_TX: {:?}", tx);
        tracing::debug!("SLASH_OR_TAKE_TX weight: {:?}", tx.tx.weight());
        let message: [u8; 32] = Actor::convert_tx_to_sighash_script_spend(&mut tx, 0, 0)
            .unwrap()
            .to_byte_array();
        tracing::debug!("aggregate SLASH_OR_TAKE_TX message: {:?}", message);
        let final_sig: [u8; 64] = aggregate_partial_signatures(
            self.config.verifiers_public_keys.clone(),
            None,
            false,
            agg_nonce,
            partial_sigs,
            message,
        )?;
        tracing::debug!("aggregate SLASH_OR_TAKE_TX final_sig: {:?}", final_sig);
        tracing::debug!(
            "aggregate SLASH_OR_TAKE_TX for verifiers: {:?}",
            self.config.verifiers_public_keys.clone()
        );
        tracing::debug!(
            "aggregate SLASH_OR_TAKE_TX for operator: {:?}",
            operator_xonly_pk
        );
        Ok(final_sig)
    }

    fn aggregate_operator_takes_partial_sigs(
        &self,
        deposit_outpoint: OutPoint,
        kickoff_utxo: UTXO,
        operator_xonly_pk: &secp256k1::XOnlyPublicKey,
        operator_idx: usize,
        agg_nonce: &MuSigAggNonce,
        partial_sigs: Vec<[u8; 32]>,
    ) -> Result<[u8; 64], BridgeError> {
        let nofn_xonly_pk = secp256k1::XOnlyPublicKey::from_musig2_pks(
            self.config.verifiers_public_keys.clone(),
            None,
            false,
        );

        let move_tx_handler = TransactionBuilder::create_move_tx(
            deposit_outpoint,
            &EVMAddress([0u8; 20]),
            Address::p2tr(
                &utils::SECP,
                *utils::UNSPENDABLE_XONLY_PUBKEY,
                None,
                self.config.network,
            )
            .as_unchecked(),
            &nofn_xonly_pk,
            self.config.network,
        );
        let bridge_fund_outpoint = OutPoint {
            txid: move_tx_handler.tx.compute_txid(),
            vout: 0,
        };
        let slash_or_take_tx_handler = TransactionBuilder::create_slash_or_take_tx(
            deposit_outpoint,
            kickoff_utxo,
            operator_xonly_pk,
            operator_idx,
            &nofn_xonly_pk,
            self.config.network,
        );
        let slash_or_take_utxo = UTXO {
            outpoint: OutPoint {
                txid: slash_or_take_tx_handler.tx.compute_txid(),
                vout: 0,
            },
            txout: slash_or_take_tx_handler.tx.output[0].clone(),
        };
        let mut tx_handler = TransactionBuilder::create_operator_takes_tx(
            bridge_fund_outpoint,
            slash_or_take_utxo,
            operator_xonly_pk,
            &nofn_xonly_pk,
            self.config.network,
        );
        tracing::debug!(
            "OPERATOR_TAKES_TX with operator_idx:{:?} {:?}",
            operator_idx,
            tx_handler.tx
        );
        tracing::debug!("OPERATOR_TAKES_TX_HEX: {:?}", tx_handler.tx.raw_hex());
        tracing::debug!("OPERATOR_TAKES_TX weight: {:?}", tx_handler.tx.weight());
        let message: [u8; 32] = Actor::convert_tx_to_sighash_pubkey_spend(&mut tx_handler, 0)
            .unwrap()
            .to_byte_array();
        let final_sig: [u8; 64] = aggregate_partial_signatures(
            self.config.verifiers_public_keys.clone(),
            None,
            true,
            agg_nonce,
            partial_sigs,
            message,
        )?;
        tracing::debug!("OPERATOR_TAKES_TX final_sig: {:?}", final_sig);
        Ok(final_sig)
    }

    fn aggregate_move_partial_sigs(
        &self,
        deposit_outpoint: OutPoint,
        evm_address: &EVMAddress,
        recovery_taproot_address: &Address<NetworkUnchecked>,
        agg_nonce: &MuSigAggNonce,
        partial_sigs: Vec<[u8; 32]>,
    ) -> Result<[u8; 64], BridgeError> {
        let musig_agg_xonly_pubkey_wrapped = secp256k1::XOnlyPublicKey::from_musig2_pks(
            self.config.verifiers_public_keys.clone(),
            None,
            false,
        );
        let mut tx = TransactionBuilder::create_move_tx(
            deposit_outpoint,
            evm_address,
            recovery_taproot_address,
            &musig_agg_xonly_pubkey_wrapped,
            self.config.network,
        );
        // println!("MOVE_TX: {:?}", tx);
        // println!("MOVE_TXID: {:?}", tx.tx.compute_txid());
        let message: [u8; 32] = Actor::convert_tx_to_sighash_script_spend(&mut tx, 0, 0)
            .unwrap()
            .to_byte_array();
        let final_sig: [u8; 64] = aggregate_partial_signatures(
            self.config.verifiers_public_keys.clone(),
            None,
            false,
            agg_nonce,
            partial_sigs,
            message,
        )?;

        Ok(final_sig)
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
            let agg_sig = self.aggregate_slash_or_take_partial_sigs(
                deposit_outpoint,
                kickoff_utxos[i].clone(),
                self.config.operators_xonly_pks[i],
                i,
                &agg_nonces[i].clone(),
                partial_sigs
                    .iter()
                    .map(|v| v.get(i).cloned().unwrap())
                    .collect::<Vec<_>>(),
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
            let agg_sig = self.aggregate_operator_takes_partial_sigs(
                deposit_outpoint,
                kickoff_utxos[i].clone(),
                &self.config.operators_xonly_pks[i].clone(),
                i,
                &agg_nonces[i].clone(),
                partial_sigs.iter().map(|v| v[i]).collect(),
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
        let agg_move_tx_final_sig = self.aggregate_move_partial_sigs(
            deposit_outpoint,
            &evm_address,
            &recovery_taproot_address,
            &agg_nonce,
            partial_sigs,
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
