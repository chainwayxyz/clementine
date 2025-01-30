//! # Script Builder
//!
//! Script builder provides useful functions for building typical Bitcoin
//! scripts.

use crate::constants::ANCHOR_AMOUNT;
use crate::EVMAddress;
use bitcoin::blockdata::opcodes::all::OP_PUSHNUM_1;
use bitcoin::opcodes::OP_TRUE;
use bitcoin::Amount;
use bitcoin::{
    opcodes::{all::*, OP_FALSE},
    script::Builder,
    ScriptBuf, TxOut, XOnlyPublicKey,
};

/// Creates a P2WSH output that anyone can spend. TODO: We will not need this in the future.
pub fn anyone_can_spend_txout() -> TxOut {
    let script = Builder::new().push_opcode(OP_PUSHNUM_1).into_script();
    let script_pubkey = script.to_p2wsh();
    let value = script_pubkey.minimal_non_dust();

    TxOut {
        script_pubkey,
        value,
    }
}

/// Creates a P2A output for CPFP.
pub fn anchor_output() -> TxOut {
    TxOut {
        value: ANCHOR_AMOUNT,
        script_pubkey: ScriptBuf::from_hex("51024e73").unwrap(),
    }
}

/// Creates a OP_RETURN output.
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

/// Creates a script with inscription tagged `citrea` that states the EVM address and amount to be deposited.
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

/// Generates a relative timelock script with a given [`XOnlyPublicKey`] that CHECKSIG checks the signature against.
///
/// ATTENTION: If you want to spend a UTXO using timelock script, the
/// condition is that (`# in the script`) ≤ (`# in the sequence of the tx`)
/// ≤ (`# of blocks mined after UTXO appears on the chain`). However, this is not mandatory.
/// One can spend an output delayed for some number of blocks just by using the nSequence field
/// of the input inside the transaction. For more, see:
///
/// - [BIP-0068](https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki)
/// - [BIP-0112](https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki)
///
/// # Parameters
///
/// - `xonly_pk`: The XonlyPublicKey that CHECKSIG checks the signature against.
/// - `block_count`: The number of blocks after which the funds can be spent.
///
/// # Returns
///
/// - [`ScriptBuf`]: The relative timelock script with signature verification
pub fn generate_checksig_relative_timelock_script(
    xonly_pk: XOnlyPublicKey,
    block_count: u16,
) -> ScriptBuf {
    Builder::new()
        .push_int(i64::from(block_count))
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_x_only_key(&xonly_pk)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// Generates a relative timelock script without a key. This means after the specified block count, the funds can be spent by anyone.
///
/// # Parameters
///
/// - `block_count`: The number of blocks after which the funds can be spent.
///
/// # Returns
///
/// - [`ScriptBuf`]: The relative timelock script without a key
pub fn generate_relative_timelock_script(block_count: i64) -> ScriptBuf {
    Builder::new()
        .push_int(block_count)
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_opcode(OP_TRUE)
        .into_script()
}

/// Generates a hashlock script. This script can be unlocked by revealing the preimage of the hash.
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

/// Generates a signature verification script.
///
/// This is a simple P2PK script that pays to the given xonly pk.
///
/// # Parameters
///
/// - `xonly_pk`: The x-only public key of the actor.
///
/// # Returns
///
/// - [`ScriptBuf`]: The script that unlocks with the given `xonly_pk`'s signature
pub fn generate_checksig_script(xonly_pk: XOnlyPublicKey) -> ScriptBuf {
    Builder::new()
        .push_x_only_key(&xonly_pk)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// WIP: This will be replaced by actual disprove scripts
pub fn dummy_script() -> ScriptBuf {
    Builder::new().push_opcode(OP_TRUE).into_script()
}
