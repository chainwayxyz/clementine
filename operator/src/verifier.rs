use bitcoin::{hashes::Hash, secp256k1, secp256k1::Secp256k1, Address, TapSighash, Txid};
use bitcoincore_rpc::Client;
use secp256k1::{rand::rngs::OsRng, XOnlyPublicKey};

use crate::{
    actor::{Actor, EVMAddress},
    operator::{check_deposit, DepositPresigns, NUM_ROUNDS},
};

use circuit_helpers::config::NUM_VERIFIERS;

pub struct Verifier<'a> {
    pub rpc: &'a Client,
    pub secp: Secp256k1<secp256k1::All>,
    pub signer: Actor,
    pub operator: XOnlyPublicKey,
    pub verifiers: Vec<XOnlyPublicKey>,
}

impl<'a> Verifier<'a> {
    pub fn new(rng: &mut OsRng, rpc: &'a Client, operator_pk: XOnlyPublicKey) -> Self {
        let signer = Actor::new(rng);
        let secp: Secp256k1<secp256k1::All> = Secp256k1::new();
        let verifiers = Vec::new();
        Verifier {
            rpc,
            secp,
            signer,
            operator: operator_pk,
            verifiers,
        }
    }

    pub fn set_verifiers(&mut self, verifiers: Vec<XOnlyPublicKey>) {
        self.verifiers = verifiers;
    }

    // this is a public endpoint that only depositor can call
    pub fn new_deposit(
        &self,
        txid: [u8; 32],
        hash: [u8; 32],
        return_address: Address,
    ) -> DepositPresigns {
        let mut all_verifiers = self.verifiers.to_vec();
        all_verifiers.push(self.operator);
        let timestamp = check_deposit(self.rpc, txid, hash, return_address, &all_verifiers);
        let kickoff_sign = self.signer.sign(TapSighash::all_zeros());
        let kickoff_txid = Txid::all_zeros();
        let mut move_bridge_sign = Vec::new();
        let mut operator_take_sign = Vec::new();
        for _ in 0..NUM_ROUNDS {
            move_bridge_sign.push(self.signer.sign(TapSighash::all_zeros()));
            operator_take_sign.push(self.signer.sign(TapSighash::all_zeros()));
        }
        let rollup_sign = self.signer.sign_deposit(
            kickoff_txid,
            timestamp.to_consensus_u32().to_be_bytes(),
            hash,
        );
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
