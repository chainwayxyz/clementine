use crate::actor::Actor;
use crate::errors::BridgeError;
use crate::extended_rpc::ExtendedRpc;

use crate::script_builder::ScriptBuilder;
use crate::transaction_builder::TransactionBuilder;

use bitcoin::secp256k1::Secp256k1;
use bitcoin::OutPoint;
use bitcoin::XOnlyPublicKey;
use circuit_helpers::constant::EVMAddress;
use secp256k1::schnorr::Signature;

use crate::config::BRIDGE_AMOUNT_SATS;
use secp256k1::rand::rngs::OsRng;

#[derive(Debug)]
pub struct User<'a> {
    pub rpc: &'a ExtendedRpc,
    pub secp: Secp256k1<secp256k1::All>,
    pub signer: Actor,
    pub transaction_builder: TransactionBuilder,
    pub script_builder: ScriptBuilder,
}

impl<'a> User<'a> {
    pub fn new(rpc: &'a ExtendedRpc, verifiers_pks: Vec<XOnlyPublicKey>) -> Self {
        let secp = Secp256k1::new();
        let signer = Actor::new(&mut OsRng);
        let transaction_builder = TransactionBuilder::new(verifiers_pks.clone());
        let script_builder = ScriptBuilder::new(verifiers_pks);
        User {
            rpc,
            secp,
            signer,
            transaction_builder,
            script_builder,
        }
    }

    pub fn deposit_tx(
        &self,
    ) -> Result<(OutPoint, XOnlyPublicKey, EVMAddress, Signature), BridgeError> {
        let (deposit_address, _) = self
            .transaction_builder
            .generate_deposit_address(&self.signer.xonly_public_key);
        let deposit_utxo = self
            .rpc
            .send_to_address(&deposit_address, BRIDGE_AMOUNT_SATS)?;
        let mut move_tx = self
            .transaction_builder
            .create_move_tx(deposit_utxo, &self.signer.evm_address);
        let move_tx_prevouts = TransactionBuilder::create_move_tx_prevouts(&deposit_address);
        let script_n_of_n_with_user_pk = self
            .script_builder
            .generate_script_n_of_n_with_user_pk(&self.signer.xonly_public_key);
        let sig = self.signer.sign_taproot_script_spend_tx(
            &mut move_tx,
            &move_tx_prevouts,
            &script_n_of_n_with_user_pk,
            0,
        )?;

        Ok((
            deposit_utxo,
            self.signer.xonly_public_key,
            self.signer.evm_address,
            sig,
        ))
    }
}

#[cfg(test)]
mod tests {}
