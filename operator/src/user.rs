use crate::actor::Actor;
use crate::extended_rpc::ExtendedRpc;

use crate::transaction_builder::TransactionBuilder;

use bitcoin::secp256k1::Secp256k1;
use bitcoin::OutPoint;
use bitcoin::XOnlyPublicKey;

use crate::config::BRIDGE_AMOUNT_SATS;
use secp256k1::rand::rngs::OsRng;

#[derive(Debug, Clone)]
pub struct User<'a> {
    pub rpc: &'a ExtendedRpc,
    pub secp: Secp256k1<secp256k1::All>,
    pub signer: Actor,
    pub transaction_builder: TransactionBuilder,
}

impl<'a> User<'a> {
    pub fn new(rpc: &'a ExtendedRpc, verifiers_pks: Vec<XOnlyPublicKey>) -> Self {
        let secp = Secp256k1::new();
        let signer = Actor::new(&mut OsRng);
        let transaction_builder = TransactionBuilder::new(verifiers_pks);
        User {
            rpc,
            secp,
            signer,
            transaction_builder,
        }
    }

    pub fn deposit_tx(&self) -> (OutPoint, XOnlyPublicKey) {
        let (deposit_address, _) = self
            .transaction_builder
            .generate_deposit_address(&self.signer.xonly_public_key);
        let deposit_utxo = self
            .rpc
            .send_to_address(&deposit_address, BRIDGE_AMOUNT_SATS);
        (deposit_utxo, self.signer.xonly_public_key)
    }
}

#[cfg(test)]
mod tests {}
