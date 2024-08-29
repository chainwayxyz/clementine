use async_trait::async_trait;
use bitcoin::{address::NetworkUnchecked, Address, OutPoint, Transaction};
use secp256k1::schnorr;

use crate::{
    config::BridgeConfig,
    errors::BridgeError,
    musig2::{
        aggregate_nonces, AggregateFromPublicKeys, MuSigAggNonce, MuSigPartialSignature,
        MuSigPubNonce,
    },
    traits::rpc::AggregatorServer,
    EVMAddress, UTXO,
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
        unimplemented!()
    }

    async fn aggregate_operator_take_sigs_rpc(
        &self,
        deposit_outpoint: OutPoint,
        kickoff_utxos: Vec<UTXO>,
        agg_nonces: Vec<MuSigAggNonce>,
        partial_sigs: Vec<Vec<MuSigPartialSignature>>,
    ) -> Result<Vec<schnorr::Signature>, BridgeError> {
        unimplemented!()
    }

    async fn aggregate_move_tx_sigs_rpc(
        &self,
        deposit_outpoint: OutPoint,
        recovery_taproot_address: Address<NetworkUnchecked>,
        evm_address: EVMAddress,
        agg_nonce: MuSigAggNonce,
        partial_sigs: Vec<MuSigPartialSignature>,
    ) -> Result<Transaction, BridgeError> {
        unimplemented!()
    }
}
