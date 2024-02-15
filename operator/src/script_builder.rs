use bitcoin::{opcodes::{all::{OP_CHECKSIGVERIFY, OP_EQUAL, OP_SHA256, OP_VERIFY}, OP_TRUE}, script::Builder, ScriptBuf};
use secp256k1::XOnlyPublicKey;

#[derive(Debug, Clone)]
pub struct ScriptBuilder {
    pub verifiers_pks: Vec<XOnlyPublicKey>,
}

impl ScriptBuilder {
    pub fn new(verifiers_pks: Vec<XOnlyPublicKey>) -> Self {
        Self {
            verifiers_pks,
        }
    }

    pub fn generate_n_of_n_script(
        &self,
        hash: [u8; 32],
    ) -> ScriptBuf {
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

    pub fn convert_scriptbuf_into_builder(script: ScriptBuf) -> Builder {
        let script_bytes = script.as_bytes().to_vec();
        Builder::from(script_bytes)
    }
}
