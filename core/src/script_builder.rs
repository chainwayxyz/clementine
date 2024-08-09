//! # Script Builder
//!
//! Script builder module includes useful functions for building Bitcoin
//! scripts.

use crate::EVMAddress;
use bitcoin::address::NetworkUnchecked;
use bitcoin::blockdata::opcodes::all::OP_PUSHNUM_1;
use bitcoin::hashes::Hash;
use bitcoin::{
    opcodes::{all::*, OP_FALSE},
    script::Builder,
    ScriptBuf, TxOut,
};
use bitcoin::{Address, OutPoint};
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

pub fn create_kickoff_commit_script(
    verifiers_pks: &[XOnlyPublicKey],
    evm_address: &EVMAddress,
    kickoff_utxos: &[OutPoint],
) -> ScriptBuf {
    let citrea: [u8; 6] = "citrea".as_bytes().try_into().unwrap();

    let builder = create_n_of_n_builder(verifiers_pks)
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF)
        .push_slice(citrea)
        .push_slice(evm_address.0);

    let builder = kickoff_utxos.iter().fold(builder, |b, utxo| {
        b.push_slice(&utxo.txid.to_raw_hash().to_byte_array()) // TODO: Optimize here
            .push_int(utxo.vout as i64)
    });

    builder.push_opcode(OP_ENDIF)
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
/// < (`# of blocks mined after UTXO`) appears on the chain.
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
