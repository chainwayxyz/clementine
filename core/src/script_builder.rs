use bitcoin::address::NetworkUnchecked;
use bitcoin::blockdata::opcodes::all::OP_PUSHNUM_1;
use bitcoin::Address;
use bitcoin::{
    opcodes::{all::*, OP_FALSE},
    script::Builder,
    ScriptBuf, TxOut,
};
use secp256k1::XOnlyPublicKey;

use crate::EVMAddress;

#[derive(Debug, Clone)]
pub struct ScriptBuilder {
    pub verifiers_pks: Vec<XOnlyPublicKey>,
}

impl ScriptBuilder {
    pub fn new(verifiers_pks: Vec<XOnlyPublicKey>) -> Self {
        Self { verifiers_pks }
    }

    pub fn anyone_can_spend_txout() -> TxOut {
        let script = Builder::new().push_opcode(OP_PUSHNUM_1).into_script();
        let script_pubkey = script.to_p2wsh();
        let value = script_pubkey.dust_value();
        TxOut {
            script_pubkey,
            value,
        }
    }

    pub fn op_return_txout(evm_address: &EVMAddress) -> TxOut {
        let script = Builder::new()
            .push_opcode(OP_RETURN)
            .push_slice(evm_address.0)
            .into_script();
        let script_pubkey = script.to_p2wsh();
        let value = script_pubkey.dust_value();
        TxOut {
            script_pubkey,
            value,
        }
    }

    pub fn create_n_of_n_builder(&self) -> Builder {
        let mut builder = Builder::new();
        let last_index = self.verifiers_pks.len() - 1;

        for &vpk in &self.verifiers_pks[..last_index] {
            builder = builder.push_x_only_key(&vpk).push_opcode(OP_CHECKSIGVERIFY);
        }
        builder = builder
            .push_x_only_key(&self.verifiers_pks[last_index])
            .push_opcode(OP_CHECKSIG);
        builder
    }

    pub fn generate_script_n_of_n(&self) -> ScriptBuf {
        self.create_n_of_n_builder().into_script()
    }

    pub fn create_deposit_script(&self, evm_address: &EVMAddress, amount: u64) -> ScriptBuf {
        let citrea: [u8; 6] = "citrea".as_bytes().try_into().unwrap();
        // println!("citrea: {:?}", citrea);
        self.create_n_of_n_builder()
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF)
            .push_slice(citrea)
            .push_slice(evm_address.0)
            .push_slice(amount.to_be_bytes())
            .push_opcode(OP_ENDIF)
            .into_script()
    }

    pub fn create_inscription_script_32_bytes(
        public_key: &XOnlyPublicKey,
        data: &Vec<[u8; 32]>,
    ) -> ScriptBuf {
        let mut inscribe_preimage_script_builder = Builder::new()
            .push_x_only_key(public_key)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF);
        for elem in data {
            inscribe_preimage_script_builder = inscribe_preimage_script_builder.push_slice(elem);
        }
        inscribe_preimage_script_builder = inscribe_preimage_script_builder.push_opcode(OP_ENDIF);

        inscribe_preimage_script_builder.into_script()
    }

    // ATTENTION: If you want to spend a UTXO using timelock script, the condition is that
    // # in the script < # in the sequence of the tx < # of blocks mined after UTXO appears on the chain

    pub fn generate_timelock_script(
        actor_taproot_address: &Address<NetworkUnchecked>,
        block_count: u32,
    ) -> ScriptBuf {
        let actor_script_pubkey = actor_taproot_address.payload().script_pubkey();
        let actor_extracted_xonly_pk =
            XOnlyPublicKey::from_slice(&actor_script_pubkey.as_bytes()[2..34]).unwrap();
        Builder::new()
            .push_int(block_count as i64)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            .push_x_only_key(&actor_extracted_xonly_pk)
            .push_opcode(OP_CHECKSIG)
            .into_script()
    }

    pub fn generate_absolute_timelock_script(
        actor_pk: &XOnlyPublicKey,
        block_count: u32,
    ) -> ScriptBuf {
        Builder::new()
            .push_int(block_count as i64)
            .push_opcode(OP_CLTV)
            .push_opcode(OP_DROP)
            .push_x_only_key(actor_pk)
            .push_opcode(OP_CHECKSIG)
            .into_script()
    }

    pub fn generate_hash_script(hash: [u8; 32]) -> ScriptBuf {
        Builder::new()
            .push_opcode(OP_SHA256)
            .push_slice(hash)
            .push_opcode(OP_EQUAL)
            .into_script()
    }

    pub fn generate_dust_script(evm_address: &EVMAddress) -> ScriptBuf {
        Builder::new()
            .push_opcode(OP_RETURN)
            .push_slice(evm_address.0)
            .into_script()
    }
}
