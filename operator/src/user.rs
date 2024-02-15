use crate::actor::Actor;
use crate::transaction_builder::TransactionBuilder;
use bitcoin::OutPoint;
use bitcoin::secp256k1::All;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::Amount;
use bitcoin::XOnlyPublicKey;
use bitcoincore_rpc::Client;
use secp256k1::rand::rngs::OsRng;
use secp256k1::rand::Rng;

#[derive(Debug, Clone)]
pub struct User<'a> {
    pub rpc: &'a Client,
    pub secp: Secp256k1<secp256k1::All>,
    pub signer: Actor,
    preimage: [u8; 32],
}

impl<'a> User<'a> {
    pub fn new(rng: &mut OsRng, rpc: &'a Client) -> Self {
        let secp = Secp256k1::new();
        let signer = Actor::new(&mut OsRng);
        let preimage: [u8; 32] = rng.gen();
        User {
            rpc,
            secp,
            signer,
            preimage,
        }
    }

    pub fn create_start_utxo(&self, rpc: &Client, amount: Amount) -> (OutPoint, Amount) {
        self.signer.create_self_utxo(rpc, amount)
    }

    pub fn deposit_tx(
        &self,
        rpc: &Client,
        start_utxo: OutPoint,
        deposit_amount: Amount,
        secp: &Secp256k1<All>,
        verifiers_pks: Vec<XOnlyPublicKey>,
        hash: [u8; 32],
    ) -> (OutPoint, XOnlyPublicKey) {
        let transaction_builder = TransactionBuilder::new(verifiers_pks);

        let (deposit_address, _) =
        transaction_builder.generate_deposit_address(self.signer.xonly_public_key, hash);

        let res = self.signer.spend_self_utxo(rpc, start_utxo, deposit_amount, deposit_address);

        (
            res.0,
            self.signer.xonly_public_key,
        )
    }

    pub fn reveal_preimage(&self) -> [u8; 32] {
        self.preimage
    }
}

#[cfg(test)]
mod tests {

}
