use crate::{
    actor::Actor,
    builder,
    config::BridgeConfig,
    database::Database,
    errors::BridgeError,
    musig2::{
        aggregate_nonces, aggregate_partial_signatures, AggregateFromPublicKeys, MuSigAggNonce,
        MuSigPartialSignature, MuSigPubNonce,
    },
    rpc::{
        self,
        clementine::{
            clementine_operator_client::ClementineOperatorClient,
            clementine_verifier_client::ClementineVerifierClient,
            clementine_watchtower_client::ClementineWatchtowerClient,
        },
    },
    utils::handle_taproot_witness_new,
    ByteArray32, ByteArray66, EVMAddress, UTXO,
};
use bitcoin::{address::NetworkUnchecked, Address, OutPoint};
use bitcoin::{hashes::Hash, Txid};
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
    pub(crate) db: Database,
    pub(crate) config: BridgeConfig,
    pub(crate) nofn_xonly_pk: secp256k1::XOnlyPublicKey,
    pub(crate) verifier_clients: Vec<ClementineVerifierClient<tonic::transport::Channel>>,
    pub(crate) operator_clients: Vec<ClementineOperatorClient<tonic::transport::Channel>>,
    pub(crate) watchtower_clients: Vec<ClementineWatchtowerClient<tonic::transport::Channel>>,
}

impl Aggregator {
    // #[tracing::instrument(err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn new(config: BridgeConfig) -> Result<Self, BridgeError> {
        let db = Database::new(&config).await?;

        let nofn_xonly_pk = secp256k1::XOnlyPublicKey::from_musig2_pks(
            config.verifiers_public_keys.clone(),
            None,
            false,
        );

        let verifier_endpoints =
            config
                .verifier_endpoints
                .clone()
                .ok_or(BridgeError::ConfigError(
                    "Couldn't find operator endpoints in config file!".to_string(),
                ))?;
        let verifier_clients =
            rpc::get_clients(verifier_endpoints, ClementineVerifierClient::connect).await?;

        let operator_endpoints =
            config
                .operator_endpoints
                .clone()
                .ok_or(BridgeError::ConfigError(
                    "Couldn't find operator endpoints in config file!".to_string(),
                ))?;
        let operator_clients =
            rpc::get_clients(operator_endpoints, ClementineOperatorClient::connect).await?;

        let watchtower_endpoints =
            config
                .watchtower_endpoints
                .clone()
                .ok_or(BridgeError::ConfigError(
                    "Couldn't find watchtower endpoints in config file!".to_string(),
                ))?;

        let watchtower_clients =
            rpc::get_clients(watchtower_endpoints, ClementineWatchtowerClient::connect).await?;

        Ok(Aggregator {
            db,
            config,
            nofn_xonly_pk,
            verifier_clients,
            operator_clients,
            watchtower_clients,
        })
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    fn aggregate_slash_or_take_partial_sigs(
        &self,
        deposit_outpoint: OutPoint,
        kickoff_utxo: UTXO,
        operator_xonly_pk: secp256k1::XOnlyPublicKey,
        operator_idx: usize,
        agg_nonce: &MuSigAggNonce,
        partial_sigs: Vec<MuSigPartialSignature>,
    ) -> Result<[u8; 64], BridgeError> {
        let mut tx = builder::transaction::create_slash_or_take_tx(
            deposit_outpoint,
            kickoff_utxo,
            operator_xonly_pk,
            operator_idx,
            self.nofn_xonly_pk,
            self.config.network,
            self.config.user_takes_after,
            self.config.operator_takes_after,
            self.config.bridge_amount_sats,
        );
        // tracing::debug!("SLASH_OR_TAKE_TX: {:?}", tx);
        tracing::debug!("SLASH_OR_TAKE_TX weight: {:?}", tx.tx.weight());
        let message: [u8; 32] =
            Actor::convert_tx_to_sighash_script_spend(&mut tx, 0, 0)?.to_byte_array();
        // tracing::debug!("aggregate SLASH_OR_TAKE_TX message: {:?}", message);
        let final_sig: [u8; 64] = aggregate_partial_signatures(
            self.config.verifiers_public_keys.clone(),
            None,
            false,
            agg_nonce,
            partial_sigs,
            ByteArray32(message),
        )?;
        // tracing::debug!("aggregate SLASH_OR_TAKE_TX final_sig: {:?}", final_sig);
        // tracing::debug!(
        //     "aggregate SLASH_OR_TAKE_TX for verifiers: {:?}",
        //     self.config.verifiers_public_keys.clone()
        // );
        // tracing::debug!(
        //     "aggregate SLASH_OR_TAKE_TX for operator: {:?}",
        //     operator_xonly_pk
        // );
        Ok(final_sig)
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    fn aggregate_operator_takes_partial_sigs(
        &self,
        deposit_outpoint: OutPoint,
        kickoff_utxo: UTXO,
        operator_xonly_pk: &secp256k1::XOnlyPublicKey,
        operator_idx: usize,
        agg_nonce: &MuSigAggNonce,
        partial_sigs: Vec<MuSigPartialSignature>,
    ) -> Result<[u8; 64], BridgeError> {
        let move_tx = builder::transaction::create_move_tx(
            deposit_outpoint,
            self.nofn_xonly_pk,
            self.config.bridge_amount_sats,
            self.config.network,
        );
        let bridge_fund_outpoint = OutPoint {
            txid: move_tx.compute_txid(),
            vout: 0,
        };
        let slash_or_take_tx_handler = builder::transaction::create_slash_or_take_tx(
            deposit_outpoint,
            kickoff_utxo,
            *operator_xonly_pk,
            operator_idx,
            self.nofn_xonly_pk,
            self.config.network,
            self.config.user_takes_after,
            self.config.operator_takes_after,
            self.config.bridge_amount_sats,
        );
        let slash_or_take_utxo = UTXO {
            outpoint: OutPoint {
                txid: slash_or_take_tx_handler.tx.compute_txid(),
                vout: 0,
            },
            txout: slash_or_take_tx_handler.tx.output[0].clone(),
        };
        // tracing::debug!(
        //     "SERDE_UTXO: {:#?}",
        //     serde_json::to_string(&slash_or_take_utxo)?
        // );

        let mut tx_handler = builder::transaction::create_operator_takes_tx(
            bridge_fund_outpoint,
            slash_or_take_utxo,
            *operator_xonly_pk,
            self.nofn_xonly_pk,
            self.config.network,
            self.config.operator_takes_after,
            self.config.bridge_amount_sats,
            self.config.operator_wallet_addresses[operator_idx].clone(),
        );
        // tracing::debug!(
        //     "OPERATOR_TAKES_TX with operator_idx:{:?} {:?}",
        //     operator_idx,
        //     tx_handler.tx
        // );
        // tracing::debug!("OPERATOR_TAKES_TX_HEX: {:?}", tx_handler.tx.raw_hex());
        tracing::debug!("OPERATOR_TAKES_TX weight: {:?}", tx_handler.tx.weight());
        let message: [u8; 32] =
            Actor::convert_tx_to_sighash_pubkey_spend(&mut tx_handler, 0)?.to_byte_array();
        let final_sig: [u8; 64] = aggregate_partial_signatures(
            self.config.verifiers_public_keys.clone(),
            None,
            true,
            agg_nonce,
            partial_sigs,
            ByteArray32(message),
        )?;
        // tracing::debug!("OPERATOR_TAKES_TX final_sig: {:?}", final_sig);
        Ok(final_sig)
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    fn aggregate_move_partial_sigs(
        &self,
        deposit_outpoint: OutPoint,
        evm_address: EVMAddress,
        recovery_taproot_address: &Address<NetworkUnchecked>,
        agg_nonce: &MuSigAggNonce,
        partial_sigs: Vec<MuSigPartialSignature>,
    ) -> Result<[u8; 64], BridgeError> {
        let mut tx = builder::transaction::create_move_txhandler(
            deposit_outpoint,
            evm_address,
            recovery_taproot_address,
            self.nofn_xonly_pk,
            self.config.user_takes_after,
            self.config.bridge_amount_sats,
            self.config.network,
        );
        // println!("MOVE_TX: {:?}", tx);
        // println!("MOVE_TXID: {:?}", tx.tx.compute_txid());
        let message: [u8; 32] =
            Actor::convert_tx_to_sighash_script_spend(&mut tx, 0, 0)?.to_byte_array();
        let final_sig: [u8; 64] = aggregate_partial_signatures(
            self.config.verifiers_public_keys.clone(),
            None,
            false,
            agg_nonce,
            partial_sigs,
            ByteArray32(message),
        )?;

        Ok(final_sig)
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn aggregate_pub_nonces(
        &self,
        pub_nonces: Vec<Vec<MuSigPubNonce>>,
    ) -> Result<Vec<MuSigAggNonce>, BridgeError> {
        let mut agg_nonces = Vec::new();
        for i in 0..pub_nonces[0].len() {
            let pub_nonces = pub_nonces
                .iter()
                .map(|v| v.get(i).cloned())
                .collect::<Option<Vec<ByteArray66>>>()
                .ok_or(BridgeError::NoncesNotFound)?;

            agg_nonces.push(aggregate_nonces(pub_nonces));
        }

        Ok(agg_nonces)
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn aggregate_slash_or_take_sigs(
        &self,
        deposit_outpoint: OutPoint,
        kickoff_utxos: Vec<UTXO>,
        agg_nonces: Vec<MuSigAggNonce>,
        partial_sigs: Vec<Vec<MuSigPartialSignature>>,
    ) -> Result<Vec<schnorr::Signature>, BridgeError> {
        tracing::debug!(
            "Aggregate slash or take sigs called with inputs: {:?}\n {:?}\n{:?}\n{:?}",
            deposit_outpoint,
            kickoff_utxos,
            agg_nonces,
            partial_sigs
        );

        let mut slash_or_take_sigs = Vec::new();
        for i in 0..partial_sigs[0].len() {
            let partial_sigs = partial_sigs
                .iter()
                .map(|v| v.get(i).cloned())
                .collect::<Option<Vec<ByteArray32>>>()
                .ok_or(BridgeError::NoncesNotFound)?;

            let agg_sig = self.aggregate_slash_or_take_partial_sigs(
                deposit_outpoint,
                kickoff_utxos[i].clone(),
                self.config.operators_xonly_pks[i],
                i,
                &agg_nonces[i].clone(),
                partial_sigs,
            )?;

            slash_or_take_sigs.push(secp256k1::schnorr::Signature::from_slice(&agg_sig)?);
        }
        Ok(slash_or_take_sigs)
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn aggregate_operator_take_sigs(
        &self,
        deposit_outpoint: OutPoint,
        kickoff_utxos: Vec<UTXO>,
        agg_nonces: Vec<MuSigAggNonce>,
        partial_sigs: Vec<Vec<MuSigPartialSignature>>,
    ) -> Result<Vec<schnorr::Signature>, BridgeError> {
        let mut operator_take_sigs = Vec::new();
        for i in 0..partial_sigs[0].len() {
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

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn aggregate_move_tx_sigs(
        &self,
        deposit_outpoint: OutPoint,
        recovery_taproot_address: Address<NetworkUnchecked>,
        evm_address: EVMAddress,
        agg_nonce: MuSigAggNonce,
        partial_sigs: Vec<MuSigPartialSignature>,
    ) -> Result<(String, Txid), BridgeError> {
        let agg_move_tx_final_sig = self.aggregate_move_partial_sigs(
            deposit_outpoint,
            evm_address,
            &recovery_taproot_address,
            &agg_nonce,
            partial_sigs,
        )?;

        let move_tx_sig = secp256k1::schnorr::Signature::from_slice(&agg_move_tx_final_sig)?;

        let mut move_tx_handler = builder::transaction::create_move_txhandler(
            deposit_outpoint,
            evm_address,
            &recovery_taproot_address,
            self.nofn_xonly_pk,
            self.config.user_takes_after,
            self.config.bridge_amount_sats,
            self.config.network,
        );
        let move_tx_witness_elements = vec![move_tx_sig.serialize().to_vec()];
        handle_taproot_witness_new(&mut move_tx_handler, &move_tx_witness_elements, 0, Some(0))?;

        let txid = move_tx_handler.txid;
        Ok((move_tx_handler.tx.raw_hex(), txid))
    }
}
