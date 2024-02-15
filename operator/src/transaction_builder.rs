use std::str::FromStr;

use bitcoin::{taproot::{TaprootBuilder, TaprootSpendInfo}, Address};
use circuit_helpers::config::USER_TAKES_AFTER;
use secp256k1::{Secp256k1, XOnlyPublicKey};

use crate::{script_builder::ScriptBuilder, utils::generate_timelock_script};
use lazy_static::lazy_static;

// This is an unspendable pubkey 
// See https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs
lazy_static! {
    pub static ref INTERNAL_KEY: XOnlyPublicKey = XOnlyPublicKey::from_str(
        "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
    )
    .unwrap();
}

#[derive(Debug, Clone)]
pub struct TransactionBuilder {
    pub secp: Secp256k1<secp256k1::All>,
    pub verifiers_pks: Vec<XOnlyPublicKey>,
    pub script_builder: ScriptBuilder,
}

impl TransactionBuilder {
    pub fn new(verifiers_pks: Vec<XOnlyPublicKey>) -> Self {
        let secp = Secp256k1::new();
        let script_builder = ScriptBuilder::new(verifiers_pks.clone());
        Self {
            secp,
            verifiers_pks,
            script_builder,
        }
    }

    pub fn generate_deposit_address(
        &self,
        user_pk: XOnlyPublicKey,
        hash: [u8; 32],
    ) -> (Address, TaprootSpendInfo) {
        let script_n_of_n = self.script_builder.generate_n_of_n_script(hash);
        let script_timelock = generate_timelock_script(user_pk, USER_TAKES_AFTER);
        let taproot = TaprootBuilder::new()
            .add_leaf(1, script_n_of_n.clone())
            .unwrap()
            .add_leaf(1, script_timelock.clone())
            .unwrap();
        let tree_info = taproot.finalize(&self.secp, *INTERNAL_KEY).unwrap();
        let address = Address::p2tr(
            &self.secp,
            *INTERNAL_KEY,
            tree_info.merkle_root(),
            bitcoin::Network::Regtest,
        );
        (address, tree_info)
    }
}
