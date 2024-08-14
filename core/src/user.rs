use crate::actor::Actor;
use crate::config::BridgeConfig;
use crate::errors::BridgeError;
use crate::extended_rpc::ExtendedRpc;
use crate::musig2::{self, MuSigAggNonce, MuSigPartialSignature, MuSigPubNonce};
use crate::transaction_builder::TransactionBuilder;
use crate::EVMAddress;
use ::musig2::secp::Point;
use bitcoin::Address;
use bitcoin::OutPoint;
use bitcoin::XOnlyPublicKey;
use bitcoin_mock_rpc::RpcApiWrapper;
use clementine_circuits::constants::BRIDGE_AMOUNT_SATS;
use secp256k1::PublicKey;
use secp256k1::SecretKey;

#[derive(Debug)]
pub struct User<R> {
    rpc: ExtendedRpc<R>,
    signer: Actor,
    transaction_builder: TransactionBuilder,
    config: BridgeConfig,
    nofn_xonly_pk: XOnlyPublicKey,
}

impl<R> User<R>
where
    R: RpcApiWrapper,
{
    /// Creates a new `User`.
    pub fn new(
        rpc: ExtendedRpc<R>,
        all_pks: Vec<PublicKey>,
        sk: SecretKey,
        config: BridgeConfig,
    ) -> Self {
        let signer = Actor::new(sk, config.network);

        let transaction_builder = TransactionBuilder::new(all_pks.clone(), config.network);

        let key_agg_context =
            musig2::create_key_agg_ctx(config.verifiers_public_keys.clone(), None).unwrap();
        let agg_point: Point = key_agg_context.aggregated_pubkey_untweaked();
        let nofn_xonly_pk =
            secp256k1::XOnlyPublicKey::from_slice(&agg_point.serialize_xonly()).unwrap();

        User {
            rpc,
            signer,
            transaction_builder,
            config,
            nofn_xonly_pk,
        }
    }

    pub fn deposit_tx(
        &self,
        evm_address: EVMAddress,
    ) -> Result<(OutPoint, XOnlyPublicKey, EVMAddress), BridgeError> {
        let (deposit_address, _) = TransactionBuilder::generate_deposit_address(
            &self.nofn_xonly_pk,
            self.signer.address.as_unchecked(),
            &evm_address,
            BRIDGE_AMOUNT_SATS,
            self.config.user_takes_after,
            self.config.network,
        );

        let deposit_utxo = self
            .rpc
            .send_to_address(&deposit_address, BRIDGE_AMOUNT_SATS)?;

        Ok((deposit_utxo, self.signer.xonly_public_key, evm_address))
    }

    pub fn get_deposit_address(&self, evm_address: EVMAddress) -> Result<Address, BridgeError> {
        let (deposit_address, _) = TransactionBuilder::generate_deposit_address(
            &self.nofn_xonly_pk,
            self.signer.address.as_unchecked(),
            &evm_address,
            BRIDGE_AMOUNT_SATS,
            self.config.user_takes_after,
            self.config.network,
        );

        Ok(deposit_address)
    }

    #[cfg(poc)]
    pub fn generate_deposit_proof(&self, _move_txid: Transaction) -> Result<(), BridgeError> {
        let out = self.rpc.get_spent_tx_out(&deposit_utxo)?;
        self.rpc.get_spent_tx_out(outpoint);
        merkle_tree::PartialMerkleTree::from_txids(&[move_txid.wtxid()], &[move_txid.txid()]);
        Ok(())
    }
}
