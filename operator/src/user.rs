use crate::actor::Actor;
use crate::utils::generate_n_of_n_script;
use bitcoin::opcodes::all::*;
use bitcoin::script::Builder;
use bitcoin::secp256k1::All;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::taproot::TaprootBuilder;
use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::Address;
use bitcoin::Amount;
use bitcoin::ScriptBuf;
use bitcoin::Transaction;
use bitcoin::XOnlyPublicKey;
use bitcoincore_rpc::Client;
use bitcoincore_rpc::RpcApi;
use circuit_helpers::config::REGTEST;
use circuit_helpers::config::USER_TAKES_AFTER;
use secp256k1::rand::Rng;
use secp256k1::rand::rngs::OsRng;
use circuit_helpers::hashes::sha256_32bytes;
use serde::de;

pub struct User<'a> {
    rpc: &'a Client,
    secp: Secp256k1<secp256k1::All>,
    pub signer: Actor,
    preimage: [u8; 32],
}

impl<'a> User<'a> {
    pub fn new(rng: &mut OsRng, rpc: &'a Client) -> Self {
        let secp = Secp256k1::new();
        let signer = Actor::new(&mut OsRng);
        let preimage: [u8; 32] = OsRng.gen();
        User { rpc, secp, signer, preimage }
    }

    pub fn generate_timelock_script(&self, block_count: u32) -> ScriptBuf {
        Builder::new()
            .push_int(block_count as i64)
            .push_opcode(OP_CSV)
            .push_x_only_key(&self.signer.xonly_public_key)
            .push_opcode(OP_CHECKSIG)
            .into_script()
    }

    pub fn generate_deposit_address(
        &self,
        secp: &Secp256k1<All>,
        verifier_pks: Vec<XOnlyPublicKey>,
        hash: [u8; 32],
    ) -> (Address, TaprootSpendInfo) {
        // println!("inputs: {:?} {:?} {:?}", secp, verifier_pks, hash);
        let script_n_of_n = generate_n_of_n_script(verifier_pks, hash);
        let script_timelock = self.generate_timelock_script(USER_TAKES_AFTER);
        let taproot = TaprootBuilder::new()
            .add_leaf(1, script_n_of_n.clone())
            .unwrap()
            .add_leaf(1, script_timelock.clone())
            .unwrap();
        let internal_key = self.signer.xonly_public_key;
        let tree_info = taproot.finalize(secp, internal_key).unwrap();
        let address = Address::p2tr(secp, internal_key, tree_info.merkle_root(), REGTEST);
        (address, tree_info)
    }

    pub fn deposit_tx(
        &self,
        rpc: &Client,
        amount: u64,
        secp: &Secp256k1<All>,
        verifiers_pks: Vec<XOnlyPublicKey>,
    ) -> (Transaction, [u8; 32], XOnlyPublicKey) {
        let hash = sha256_32bytes(self.preimage);
        let deposit_address = self.generate_deposit_address(secp, verifiers_pks, hash);
        // println!("deposit address: {:?}", deposit_address.0);
        // println!("deposit address script spend info: {:?}", deposit_address.1);
        // println!("deposit address script_pubkey: {:?}", deposit_address.0.script_pubkey());
        let initial_tx_id = rpc
            .send_to_address(
                &deposit_address.0,
                Amount::from_sat(amount),
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap_or_else(|e| panic!("Failed to send to address: {}", e));
        let initial_tx = rpc
            .get_raw_transaction(&initial_tx_id, None)
            .unwrap_or_else(|e| panic!("Failed to get transaction: {}", e));

        // println!("initial tx = {:?}", initial_tx);
        (initial_tx, hash, self.signer.xonly_public_key)
    }

    pub fn reveal_preimage(&self) -> [u8; 32] {
        self.preimage
    }

}
#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::rand::rngs::OsRng;
    use bitcoincore_rpc::Auth;

    use crate::operator::Operator;

    use super::*;

    #[test]
    fn test_deposit_tx() {
        let rpc = Client::new(
            "http://localhost:18443/wallet/admin",
            Auth::UserPass("admin".to_string(), "admin".to_string()),
        )
        .unwrap_or_else(|e| panic!("Failed to connect to Bitcoin RPC: {}", e));
        let operator = Operator::new(&mut OsRng, &rpc);
        let user = User::new(&mut OsRng, &rpc);
        let amount = 100_000_000;
        let mut verifiers = operator.verifiers.clone();
        verifiers.push(operator.signer.xonly_public_key.clone());
        let (tx, hash, return_address) =
            user.deposit_tx(&user.rpc, amount, &user.secp, verifiers);
        let mine_block = rpc.generate_to_address(1, &operator.signer.address).unwrap();
        let signatures = operator.new_deposit(&user, tx.txid(), hash, return_address);
        // TEST IF SIGNATURES ARE VALID
        // operator.preimage_revealed(preimage, txid);
    }
}
