
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
use crate::actor::Actor;
use circuit_helpers::config::REGTEST;

pub struct User<'a> {
    rpc: &'a Client,
    secp: &'a Secp256k1<secp256k1::All>,
    signer: Actor,
}

impl<'a> User<'a> {
    pub fn new(rpc: &Client, secp: &Secp256k1<All>, signer: Actor) -> Self {
        User {
            rpc,
            secp,
            signer,
        }
    }

    pub fn generate_n_of_n_script(verifiers_pks: Vec<XOnlyPublicKey>, hash: [u8; 32]) -> ScriptBuf {
        let mut builder = Builder::new();
        for vpk in verifiers_pks {
            builder = builder.push_x_only_key(&vpk).push_opcode(OP_CHECKSIGVERIFY);
        }
        // builder = builder.push_x_only_key(&verifiers_pks[0]).push_opcode(OP_CHECKSIGVERIFY);
        builder = builder
            .push_opcode(OP_SHA256)
            .push_slice(hash)
            .push_opcode(OP_EQUAL);
    
        builder.into_script()
    }

    pub fn generate_timelock_script(&self, block_count: u32) -> ScriptBuf {
        Builder::new()
            .push_int(block_count as i64)
            .push_opcode(OP_CSV)
            .push_x_only_key(&self.signer.xonly_public_key)
            .push_opcode(OP_CHECKSIG)
            .into_script()
    }
    
    pub fn generate_dust_script(eth_address: [u8; 20]) -> ScriptBuf {
        Builder::new()
            .push_opcode(OP_RETURN)
            .push_slice(&eth_address)
            .into_script()
    }
    
    pub fn generate_deposit_address(
        &self,
        secp: &Secp256k1<All>,
        verifier_pks: Vec<XOnlyPublicKey>,
        hash: [u8; 32],
    ) -> (Address, TaprootSpendInfo) {
        let script_n_of_n = User::generate_n_of_n_script(verifier_pks, hash);
        let script_timelock = self.generate_timelock_script(150);
        let taproot = TaprootBuilder::new()
            .add_leaf(1, script_n_of_n.clone())
            .unwrap()
            .add_leaf(1, script_timelock.clone())
            .unwrap();
        let internal_key = self.signer.xonly_public_key;
        let tree_info = taproot.finalize(secp, internal_key).unwrap();
        let address = Address::p2tr(
            secp,
            internal_key,
            tree_info.merkle_root(),
            REGTEST,
        );
        (address, tree_info)
    }
    
    pub fn deposit_tx(
        &self,
        rpc: &Client,
        amount: u64,
        secp: &Secp256k1<All>,
        verifier_pks: Vec<XOnlyPublicKey>,
        hash: [u8; 32],
    ) -> Transaction {
        let deposit_address = self.generate_deposit_address(secp, verifier_pks, hash);
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
    
        println!("initial tx = {:?}", initial_tx);
        initial_tx
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
        let secp = Secp256k1::new();
        let signer = Actor::new(&mut OsRng);
        let operator = Operator::new( &mut OsRng, &rpc);
        let user = User {
            rpc,
            secp,
            signer,
        };
        let amount = 10_000_000;
        let tx = user.deposit_tx(&user.rpc, amount, &user.secp, operator.verifiers, [0; 32]);
        operator.new_deposit(tx.txid(), hash, return_address)
    }
}
