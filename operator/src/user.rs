use crate::actor::Actor;
use crate::utils::create_taproot_address;
use crate::utils::create_utxo;
use crate::utils::generate_n_of_n_script;
use bitcoin::OutPoint;
use bitcoin::opcodes::all::*;
use bitcoin::script::Builder;
use bitcoin::secp256k1::All;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::Address;
use bitcoin::Amount;
use bitcoin::ScriptBuf;
use bitcoin::XOnlyPublicKey;
use bitcoincore_rpc::Client;
use bitcoincore_rpc::RpcApi;
use circuit_helpers::config::USER_TAKES_AFTER;
use circuit_helpers::constant::HASH_FUNCTION_32;
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

    pub fn generate_timelock_script(block_count: u32, public_key: XOnlyPublicKey) -> ScriptBuf {
        Builder::new()
            .push_int(block_count as i64)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            .push_x_only_key(&public_key)
            .push_opcode(OP_CHECKSIG)
            .into_script()
    }

    pub fn generate_deposit_address(
        secp: &Secp256k1<All>,
        verifiers_pks: &Vec<XOnlyPublicKey>,
        hash: [u8; 32],
        public_key: XOnlyPublicKey,
    ) -> (Address, TaprootSpendInfo) {
        // println!("inputs: {:?} {:?} {:?}", secp, verifier_pks, hash);
        let script_n_of_n = generate_n_of_n_script(&verifiers_pks, hash);
        let script_timelock = User::generate_timelock_script(USER_TAKES_AFTER, public_key);
        create_taproot_address(secp, vec![script_n_of_n, script_timelock])
    }

    pub fn deposit_tx(
        &self,
        rpc: &Client,
        amount: Amount,
        secp: &Secp256k1<All>,
        verifiers_pks: Vec<XOnlyPublicKey>,
    ) -> (OutPoint, [u8; 32], XOnlyPublicKey) {
        let hash = HASH_FUNCTION_32(self.preimage);
        let (deposit_address, _) =
            User::generate_deposit_address(secp, &verifiers_pks, hash, self.signer.xonly_public_key);
        // println!("deposit address: {:?}", deposit_address.0);
        // println!("deposit address script spend info: {:?}", deposit_address.1);
        // println!("deposit address script_pubkey: {:?}", deposit_address.0.script_pubkey());
        let initial_tx_id = rpc
            .send_to_address(
                &deposit_address,
                amount,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap_or_else(|e| panic!("Failed to send to address: {}", e));
        let initial_tx = rpc
            .get_transaction(&initial_tx_id, None)
            .unwrap_or_else(|e| panic!("Failed to get transaction: {}", e));
        // get the vout of the deposit tx
        let found_output_index = initial_tx
            .details
            .iter()
            .position(|x| {
                x.address
                    .as_ref()
                    .is_some_and(|address| address == &deposit_address)
            })
            .unwrap();
        let vout = initial_tx.details[found_output_index].vout;
        (
            create_utxo(initial_tx_id, vout),
            hash,
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
