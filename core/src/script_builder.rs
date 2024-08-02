//! # Script Builder
//!
//! Script builder module includes useful functions for building Bitcoin
//! scripts.

use crate::EVMAddress;
use bitcoin::address::NetworkUnchecked;
use bitcoin::blockdata::opcodes::all::OP_PUSHNUM_1;
use bitcoin::Address;
use bitcoin::{
    opcodes::{all::*, OP_FALSE},
    script::Builder,
    ScriptBuf, TxOut,
};
use secp256k1::XOnlyPublicKey;

pub fn anyone_can_spend_txout() -> TxOut {
    let script = Builder::new().push_opcode(OP_PUSHNUM_1).into_script();
    let script_pubkey = script.to_p2wsh();
    let value = script_pubkey.minimal_non_dust();

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
    let value = script_pubkey.minimal_non_dust();

    TxOut {
        script_pubkey,
        value,
    }
}

pub fn create_n_of_n_builder(verifiers_pks: &[XOnlyPublicKey]) -> Builder {
    let mut builder = Builder::new();
    let last_index = verifiers_pks.len() - 1;

    for &vpk in &verifiers_pks[..last_index] {
        builder = builder.push_x_only_key(&vpk).push_opcode(OP_CHECKSIGVERIFY);
    }
    builder = builder
        .push_x_only_key(&verifiers_pks[last_index])
        .push_opcode(OP_CHECKSIG);

    builder
}

pub fn generate_script_n_of_n(verifiers_pks: &[XOnlyPublicKey]) -> ScriptBuf {
    create_n_of_n_builder(verifiers_pks).into_script()
}

pub fn create_deposit_script(
    verifiers_pks: &[XOnlyPublicKey],
    evm_address: &EVMAddress,
    amount: u64,
) -> ScriptBuf {
    let citrea: [u8; 6] = "citrea".as_bytes().try_into().unwrap();

    create_n_of_n_builder(verifiers_pks)
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

/// ATTENTION: If you want to spend a UTXO using timelock script, the
/// condition is that (`# in the script`) < (`# in the sequence of the tx`)
/// < (`# of blocks mined after UTXO appears on the chain`).
pub fn generate_timelock_script(
    actor_taproot_address: &Address<NetworkUnchecked>,
    block_count: u32,
) -> ScriptBuf {
    let actor_script_pubkey = actor_taproot_address
        .clone()
        .assume_checked()
        .script_pubkey();
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

pub fn generate_absolute_timelock_script(actor_pk: &XOnlyPublicKey, block_count: u32) -> ScriptBuf {
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

pub fn generate_challenger_takes_after_script(
    challenger_xonly_pk: &XOnlyPublicKey,
    block_count: u32,
) -> ScriptBuf {
    Builder::new()
        .push_int(block_count as i64)
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_x_only_key(&challenger_xonly_pk)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

pub fn generate_dummy_commit_script(
    verifiers_pks: &[XOnlyPublicKey]
) -> ScriptBuf {
    let mut builder = Builder::new();
    for &vpk in verifiers_pks {
        builder = builder.push_x_only_key(&vpk).push_opcode(OP_CHECKSIGVERIFY);
    }
    let musig_part = builder.into_bytes();
    let bitvm_part = hex::decode("14865e91f24c6ec441f01ed04b764385e48108304c5814985dc0d964a56655af63e66eaafab9f01b2c85b453146ec3dba02c692fa682ce79bb4ceeedbdd9aa31cb57145c8d0790b0730d3290a78e07502c06511d8521f95c14acef459604ff1f304439e9a32ea68b93d5f630a20014ea9a78eab619d2083df179c75a86f687861c35be0014151f168ef4795416c669d77b49a8651c18c6021300147ca4b0b440ca70cfcf32a4f0e67e2174fa26b3c10014d84820dfa60baf7ba34ef849c225b86a8aaee0ca0014cbf34f81799254df30ad8853aaeed2fc14a55e355514ee87143027e0c67c4eb59cf96833f8f5d6b7c3255a5fa3766b6b76a976a976a976a976a976a976a976a976a976a976a976a976a976a976a96c7914cfe55f0d7f55fb10b5ab95f7b370b986940a5f88886d6d6d6d6d6d6d6d5fa3766b6b76a976a976a976a976a976a976a976a976a976a976a976a976a976a976a96c7914799e5adde121f6e0d29a32e5adeab5614e3fd418886d6d6d6d6d6d6d6d5fa3766b6b76a976a976a976a976a976a976a976a976a976a976a976a976a976a976a96c7914be4f5c0539153982dcd046ebfac41eb9ffd6f040886d6d6d6d6d6d6d6d5fa3766b6b76a976a976a976a976a976a976a976a976a976a976a976a976a976a976a96c7914746cc0daab0217da8556e3e646ee7ed2050bcd70886d6d6d6d6d6d6d6d5fa3766b6b76a976a976a976a976a976a976a976a976a976a976a976a976a976a976a96c7914773c571d3dc4745d887db4fd3e2b024e8710bc85886d6d6d6d6d6d6d6d5fa3766b6b76a976a976a976a976a976a976a976a976a976a976a976a976a976a976a96c791426ffff405d264d81dcd1d306258a42d8e1929edd886d6d6d6d6d6d6d6d5fa3766b6b76a976a976a976a976a976a976a976a976a976a976a976a976a976a976a96c791453f8bf07ef9e4317a8bcfa696ee5004008c89bfa886d6d6d6d6d6d6d6d5fa3766b6b76a976a976a976a976a976a976a976a976a976a976a976a976a976a976a96c791470c075882caf0aefb0cb2c96c76ee7551712a6e1886d6d6d6d6d6d6d6d5fa3766b6b76a976a976a976a976a976a976a976a976a976a976a976a976a976a976a96c7914cc24625ed2f9ad63bbe49fd8cce10dfa452f1660886d6d6d6d6d6d6d6d5fa3766b6b76a976a976a976a976a976a976a976a976a976a976a976a976a976a976a96c7914577cecbd65b5557e284ed647d5f1492415511bcd886d6d6d6d6d6d6d6d5fa3766b6b76a976a976a976a976a976a976a976a976a976a976a976a976a976a976a96c791486502e23fe6eff305e5b2625a5b762c634eb5258886d6d6d6d6d6d6d6d6c768f6c7d946c7d946c7d946c7d946c7d946c7d946c7d940178936c76937693769376936c9376937693769376936c9388769376937693769393769376937693769393769376937693769393769376937693769393769376937693769393769376937693769393769376937693769393").unwrap();
    let script_vec = [&musig_part[..], &bitvm_part[..]].concat();
    ScriptBuf::from(script_vec)
}
