use bitcoin::{secp256k1::{Secp256k1}, secp256k1, Address, TapSighash, Txid, hashes::Hash};
use bitcoincore_rpc::Client;

use crate::{actor::Actor, operator::{DepositPresigns, check_deposit, NUM_ROUNDS}};

use circuit_helpers::config::NUM_VERIFIERS;


pub struct Verifier {
    rpc: Client,
    secp: Secp256k1<secp256k1::All>,
    signer: Actor,
    verifier_evm_address: [u8; 32],
    operator: secp256k1::PublicKey,
    verifiers: [secp256k1::PublicKey; NUM_VERIFIERS],
}



impl Verifier {
    // this is a public endpoint that only depositor can call
    pub fn new_deposit(
        self,
        txid: [u8; 32],
        hash: [u8; 32],
        return_address: Address,
    ) -> DepositPresigns {
        let mut all_verifiers = self.verifiers.to_vec();
        all_verifiers.push(self.operator);
        let timestamp = check_deposit(
            self.rpc,
            txid,
            hash,
            return_address,
            vec![self.signer.public_key],
        );
        let kickoff_sign = self.signer.sign(TapSighash::all_zeros());
        let kickoff_txid = Txid::all_zeros();
        let mut move_bridge_sign = Vec::new();
        let mut operator_take_sign = Vec::new();
        for _ in 0..NUM_ROUNDS {
            move_bridge_sign.push(self.signer.sign(TapSighash::all_zeros()));
            operator_take_sign.push(self.signer.sign(TapSighash::all_zeros()));
        }
        let rollup_sign =
            self.signer
                .sign_deposit(kickoff_txid, timestamp.to_consensus_u32().to_be_bytes(), hash);
        DepositPresigns {
            rollup_sign,
            kickoff_sign,
            kickoff_txid,
            move_bridge_sign,
            operator_take_sign,
        }
    }

    // This is a function to reduce gas costs when moving bridge funds
    pub fn do_me_a_favor() {}
}
