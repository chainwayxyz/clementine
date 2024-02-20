use bitcoin::{
    opcodes::{all::*, OP_FALSE, OP_TRUE},
    script::Builder,
    Amount, ScriptBuf, TxOut,
};
use circuit_helpers::constant::EVMAddress;
use secp256k1::XOnlyPublicKey;

#[derive(Debug, Clone)]
pub struct ScriptBuilder {
    pub verifiers_pks: Vec<XOnlyPublicKey>,
}

impl ScriptBuilder {
    pub fn new(verifiers_pks: Vec<XOnlyPublicKey>) -> Self {
        Self { verifiers_pks }
    }

    pub fn anyone_can_spend_txout() -> TxOut {
        let script = Builder::new().push_opcode(OP_TRUE).into_script();
        let script_pubkey = script.to_p2wsh();
        let value = script.dust_value();
        TxOut {
            script_pubkey,
            value,
        }
    }

    pub fn generate_n_of_n_script(&self, hash: [u8; 32]) -> ScriptBuf {
        let raw_script = self.generate_n_of_n_script_without_hash();
        let script_buf = ScriptBuilder::convert_scriptbuf_into_builder(raw_script).into_script();
        ScriptBuilder::add_hash_to_script(script_buf, hash)
    }

    pub fn generate_n_of_n_script_without_hash(&self) -> ScriptBuf {
        let mut builder = Builder::new();
        for vpk in self.verifiers_pks.clone() {
            builder = builder.push_x_only_key(&vpk).push_opcode(OP_CHECKSIGVERIFY);
        }
        builder = builder.push_opcode(OP_TRUE);
        builder.into_script()
    }

    pub fn add_hash_to_script(script: ScriptBuf, hash: [u8; 32]) -> ScriptBuf {
        let script_bytes = script.as_bytes().to_vec();
        let mut builder = Builder::from(script_bytes);
        builder = builder.push_opcode(OP_VERIFY);
        builder = builder
            .push_opcode(OP_SHA256)
            .push_slice(hash)
            .push_opcode(OP_EQUAL);
        builder.into_script()
    }

    pub fn create_inscription_script_32_bytes(
        public_key: XOnlyPublicKey,
        data: Vec<[u8; 32]>,
    ) -> ScriptBuf {
        let mut inscribe_preimage_script_builder = Builder::new()
            .push_x_only_key(&public_key)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF);
        for elem in data {
            inscribe_preimage_script_builder = inscribe_preimage_script_builder.push_slice(&elem);
        }
        inscribe_preimage_script_builder = inscribe_preimage_script_builder.push_opcode(OP_ENDIF);
        let inscribe_preimage_script = inscribe_preimage_script_builder.into_script();
        inscribe_preimage_script
    }

    pub fn convert_scriptbuf_into_builder(script: ScriptBuf) -> Builder {
        let script_bytes = script.as_bytes().to_vec();
        Builder::from(script_bytes)
    }

    pub fn generate_timelock_script(actor_pk: XOnlyPublicKey, block_count: u32) -> ScriptBuf {
        Builder::new()
            .push_int(block_count as i64)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            .push_x_only_key(&actor_pk)
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

    pub fn generate_dust_script(evm_address: EVMAddress) -> ScriptBuf {
        Builder::new()
            .push_opcode(OP_RETURN)
            .push_slice(&evm_address)
            .into_script()
    }
}
