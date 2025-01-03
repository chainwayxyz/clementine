//! # Script Builder
//!
//! Script builder provides useful functions for building typical Bitcoin
//! scripts.

use crate::EVMAddress;
use bitcoin::blockdata::opcodes::all::OP_PUSHNUM_1;
use bitcoin::opcodes::OP_TRUE;
use bitcoin::Amount;
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

pub fn op_return_txout<S: AsRef<bitcoin::script::PushBytes>>(slice: S) -> TxOut {
    let script = Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(slice)
        .into_script();

    TxOut {
        value: Amount::from_sat(0),
        script_pubkey: script,
    }
}

pub fn create_deposit_script(
    nofn_xonly_pk: XOnlyPublicKey,
    evm_address: EVMAddress,
    amount: Amount,
) -> ScriptBuf {
    let citrea: [u8; 6] = "citrea".as_bytes().try_into().unwrap();

    Builder::new()
        .push_x_only_key(&nofn_xonly_pk)
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF)
        .push_slice(citrea)
        .push_slice(evm_address.0)
        .push_slice(amount.to_sat().to_be_bytes())
        .push_opcode(OP_ENDIF)
        .into_script()
}

pub fn create_musig2_and_operator_multisig_script(
    nofn_xonly_pk: XOnlyPublicKey,
    operator_xonly_pk: XOnlyPublicKey,
) -> ScriptBuf {
    Builder::new()
        .push_x_only_key(&nofn_xonly_pk)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_x_only_key(&operator_xonly_pk)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// ATTENTION: If you want to spend a UTXO using timelock script, the
/// condition is that (`# in the script`) < (`# in the sequence of the tx`)
/// < (`# of blocks mined after UTXO`) appears on the chain.
pub fn generate_relative_timelock_script(
    actor_taproot_xonly_pk: XOnlyPublicKey, // This is the tweaked XonlyPublicKey, which appears in the script_pubkey of the address
    block_count: i64,
) -> ScriptBuf {
    Builder::new()
        .push_int(block_count)
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_x_only_key(&actor_taproot_xonly_pk)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

pub fn actor_with_preimage_script(
    actor_taproot_xonly_pk: XOnlyPublicKey,
    hash: &[u8; 20],
) -> ScriptBuf {
    Builder::new()
        .push_opcode(OP_HASH160)
        .push_slice(hash)
        .push_opcode(OP_EQUALVERIFY)
        .push_x_only_key(&actor_taproot_xonly_pk)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

pub fn checksig_script(actor_taproot_xonly_pk: XOnlyPublicKey) -> ScriptBuf {
    Builder::new()
        .push_x_only_key(&actor_taproot_xonly_pk)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

pub fn dummy_script() -> ScriptBuf {
    Builder::new().push_opcode(OP_TRUE).into_script()
}
