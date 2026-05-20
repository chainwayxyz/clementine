//! # builder::transaction
//!
//!
//! This module provides the core logic for constructing, handling, and signing the various Bitcoin transactions
//! required by the Clementine bridge protocol. It defines the creation, and validation of
//! transaction flows involving operators, verifiers, watchtowers, and the security council, aimed to make it
//! easy to create transactions and sign them properly.
//!
//! ## Overview
//!
//! The transaction builder is responsible for:
//! - Defining all transaction types and their flows in the protocol (see [`TransactionType`]).
//! - Building and signing transactions for deposit, withdrawal, challenge, reimbursement, and related operations.
//! - Storing transaction inputs/outputs, scripts, and Taproot spend information.
//! - Providing utilities to speed up transaction creating during a deposit using caching tx and db data.
//!
//! ## Main Components
//!
//! - [`mod.rs`] - The main entry point, re-exporting native `tx-builder` types and Clementine-specific helpers for creating taproot outputs.
//! - [`creator.rs`] - Contains the functions to create multiple transaction handlers for a deposit and related structs for caching. In particular, it contains the functions to create handlers for all transactions generated during a deposit from a single kickoff.
//! - [`operator_assert.rs`] - Provides functions for creating BitVM assertion and timeout transactions.
//! - [`challenge.rs`] - Handles the creation of challenge, disprove, and watchtower challenge transactions, supporting protocol dispute resolution and fraud proofs.
//! - [`sign.rs`] - Contains logic for signing transactions using data in the [`TxHandler`].
//! - Input metadata on [`SpendSpec`] identifies who signs each input and with which sighash type.
//!

use crate::builder::address::calculate_taproot_leaf_depths;
use crate::constants::NON_EPHEMERAL_ANCHOR_AMOUNT;
use crate::protocol::ids::{Actor, Input, Leaf, Output, TransactionType};
use crate::protocol::spec::SpendSpec;
use bitcoin::hashes::Hash;
use bitcoin::opcodes::all::OP_RETURN;
use bitcoin::script::Builder;
use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::{Address, Amount, ScriptBuf, TxOut, XOnlyPublicKey};
use std::sync::Arc;
use tx_builder::input::SpendableTxIn as RuntimeSpendableTxIn;
use tx_builder::output::UnspentTxOut as RuntimeUnspentTxOut;
use tx_builder::script::{ScriptLeaf, ScriptNode};
use tx_builder::txhandler::{
    InputSighash as RuntimeInputSighash, TxHandler as RuntimeTxHandler,
    TxHandlerBuilder as RuntimeTxHandlerBuilder,
};

// Exports to the outside.
pub use clementine_primitives::DEFAULT_SEQUENCE;
pub use creator::{
    BuildContextView, DepositBuildContext, KickoffBuildContext, KickoffWinternitzKeys,
    ReplacementDepositBuildContext, ReplacementDepositBuildData, RoundBuildContext, TxCache,
    TxCacheExt, TxContextLoader, WithdrawalBuildContext, WithdrawalData,
};
pub type SpendableTxIn = RuntimeSpendableTxIn<Leaf>;
pub type UnspentTxOut = RuntimeUnspentTxOut<Leaf>;
pub type TxHandler = RuntimeTxHandler<TransactionType, Input, Output, Leaf, Actor>;
pub type TxHandlerBuilder = RuntimeTxHandlerBuilder<TransactionType, Input, Output, Leaf, Actor>;
pub type InputSighash = RuntimeInputSighash<Input>;
pub use crate::protocol::create::{
    build_batch, build_batch_cached, build_burn_unused_kickoff_connectors, build_tx,
    build_watchtower_challenge, BatchName,
};

pub(crate) trait DataSources: creator::BuildContextView {}
impl<T> DataSources for T where T: creator::BuildContextView {}

pub mod input {
    pub use super::SpendableTxIn;
}

pub mod output {
    pub use super::UnspentTxOut;
}

mod creator;
pub mod custom;
pub mod sign;

type HiddenNode<'a> = &'a [u8; 32];

pub fn input_descriptor(spend: SpendSpec) -> SpendSpec {
    spend
}

pub fn spendable_txin(
    previous_output: bitcoin::OutPoint,
    prevout: TxOut,
    scripts: Vec<ScriptNode>,
    named_leaves: Vec<(Leaf, ScriptLeaf)>,
    spend_info: Option<TaprootSpendInfo>,
) -> SpendableTxIn {
    let output = UnspentTxOut::new(prevout, scripts, named_leaves, spend_info.map(Arc::new));
    SpendableTxIn::from_output(previous_output, &output)
}

pub fn spendable_txin_from_scripts(
    previous_output: bitcoin::OutPoint,
    value: Amount,
    scripts: Vec<ScriptNode>,
    key_path: Option<XOnlyPublicKey>,
    network: bitcoin::Network,
) -> SpendableTxIn {
    let output = unspent_txout_from_scripts(value, scripts, key_path, network);
    SpendableTxIn::from_output(previous_output, &output)
}

pub fn unspent_txout(
    txout: TxOut,
    scripts: Vec<ScriptNode>,
    named_leaves: Vec<(Leaf, ScriptLeaf)>,
    spend_info: Option<TaprootSpendInfo>,
) -> UnspentTxOut {
    UnspentTxOut::new(txout, scripts, named_leaves, spend_info.map(Arc::new))
}

pub fn unspent_txout_from_scripts(
    value: Amount,
    scripts: Vec<ScriptNode>,
    key_path: Option<XOnlyPublicKey>,
    network: bitcoin::Network,
) -> UnspentTxOut {
    UnspentTxOut::from_scripts(value, scripts, key_path, network)
}

/// Creates a P2A (anchor) output for Child Pays For Parent (CPFP) fee bumping.
///
/// # Returns
///
/// A [`TxOut`] with a statically defined script and value, used as an anchor output in protocol transactions. The TxOut is spendable by anyone.
pub fn anchor_output(amount: Amount) -> TxOut {
    TxOut {
        value: amount,
        script_pubkey: ScriptBuf::from_hex("51024e73").expect("statically valid script"),
    }
}

/// A non-ephemeral anchor output. It is used in tx's that should have a non-ephemeral anchor.
/// Because ephemeral anchors force the tx to have 0 fee.
pub fn non_ephemeral_anchor_output() -> TxOut {
    TxOut {
        value: NON_EPHEMERAL_ANCHOR_AMOUNT,
        script_pubkey: ScriptBuf::from_hex("51024e73").expect("statically valid script"),
    }
}

/// Creates an OP_RETURN output with the given data slice.
///
/// # Arguments
///
/// * `slice` - The data to embed in the OP_RETURN output.
///
/// # Returns
///
/// A [`TxOut`] with an OP_RETURN script containing the provided data.
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

/// Creates Taproot spend info for a disprove path from the revealed BitVM disprove scripts.
///
/// # Arguments
///
/// * `operator_timeout_script` - The operator timeout script.
/// * `additional_script` - An additional script to include in the Taproot tree. This single additional script is generated by Clementine bridge in addition to the disprove scripts coming from BitVM side.
/// * `disprove_scripts` - The full BitVM disprove scripts to include in the taptree.
///
/// # Returns
///
/// A [`TaprootSpendInfo`] for deriving control blocks and spend proofs.
pub fn create_disprove_taproot_spend_info(
    operator_timeout_script: ScriptBuf,
    additional_script: ScriptBuf,
    disprove_scripts: &[ScriptBuf],
) -> TaprootSpendInfo {
    use crate::bitvm_client::{SECP, UNSPENDABLE_XONLY_PUBKEY};
    use bitcoin::taproot::TaprootBuilder;

    let mut builder = TaprootBuilder::new();

    builder = builder
        .add_leaf(1, operator_timeout_script)
        .expect("add operator timeout script")
        .add_leaf(2, additional_script)
        .expect("add additional script");

    // Calculate depths for the disprove subtree relative to the common depth-2 branch.
    let depths = calculate_taproot_leaf_depths(disprove_scripts.len());

    for (depth, script) in depths.into_iter().zip(disprove_scripts.iter()) {
        let main_tree_depth = 2 + depth;
        builder = builder
            .add_leaf(main_tree_depth, script.clone())
            .expect("add inlined disprove script");
    }

    builder
        .finalize(&SECP, *UNSPENDABLE_XONLY_PUBKEY)
        .expect("valid taptree")
}

/// Helper function to create a Taproot output that combines a single script and a root hash containing any number of scripts.
/// The main use case for this function is to speed up the tx creating during a deposit. We don't need to create and combine all the
/// scripts in the taproot repeatedly, but cache and combine the common scripts for each kickoff tx to a root hash, and add an additional script
/// that depends on the specific operator or nofn_pk that is signing the deposit.
///
/// # Arguments
///
/// * `script` - The one additional script to include in the merkle tree.
/// * `hidden_node` - The root hash for the merkle tree node. The node can contain any number of scripts.
/// * `amount` - The output amount.
/// * `network` - The Bitcoin network.
///
/// # Returns
///
/// An [`UnspentTxOut`] representing the Taproot TxOut.
pub fn create_taproot_output_with_hidden_node(
    script: ScriptLeaf,
    hidden_node: HiddenNode,
    amount: Amount,
    network: bitcoin::Network,
) -> UnspentTxOut {
    use crate::bitvm_client::{SECP, UNSPENDABLE_XONLY_PUBKEY};
    use bitcoin::taproot::{TapNodeHash, TaprootBuilder};

    let builder = TaprootBuilder::new()
        .add_leaf(1, script.to_script_buf())
        .expect("empty taptree will accept a script node")
        .add_hidden_node(1, TapNodeHash::from_byte_array(*hidden_node))
        .expect("taptree with one node will accept a node at depth 1");

    let taproot_spend_info = builder
        .finalize(&SECP, *UNSPENDABLE_XONLY_PUBKEY)
        .expect("cannot fail since it is a valid taptree");

    let address = Address::p2tr(
        &SECP,
        *UNSPENDABLE_XONLY_PUBKEY,
        taproot_spend_info.merkle_root(),
        network,
    );

    unspent_txout(
        TxOut {
            value: amount,
            script_pubkey: address.script_pubkey(),
        },
        vec![script.into()],
        vec![],
        Some(taproot_spend_info),
    )
}

#[cfg(test)]
mod tests {
    use crate::deposit::SecurityCouncil;
    use bitcoin::secp256k1::XOnlyPublicKey;
    use std::str::FromStr;

    #[test]
    fn test_security_council_from_str() {
        // Create some test public keys
        let pk1 = XOnlyPublicKey::from_slice(&[1; 32]).unwrap();
        let pk2 = XOnlyPublicKey::from_slice(&[2; 32]).unwrap();

        // Test valid input
        let input = format!(
            "2:{},{}",
            hex::encode(pk1.serialize()),
            hex::encode(pk2.serialize())
        );
        let council = SecurityCouncil::from_str(&input).unwrap();
        assert_eq!(council.threshold, 2);
        assert_eq!(council.pks.len(), 2);
        assert_eq!(council.pks[0], pk1);
        assert_eq!(council.pks[1], pk2);

        // Test invalid threshold
        let input = format!(
            "3:{},{}",
            hex::encode(pk1.serialize()),
            hex::encode(pk2.serialize())
        );
        assert!(SecurityCouncil::from_str(&input).is_err());

        // Test invalid hex
        let input = "2:invalid,pk2";
        assert!(SecurityCouncil::from_str(input).is_err());

        // Test missing parts
        assert!(SecurityCouncil::from_str("2").is_err());
        assert!(SecurityCouncil::from_str(":").is_err());

        // Test too many parts
        let input = format!(
            "2:{},{}:extra",
            hex::encode(pk1.serialize()),
            hex::encode(pk2.serialize())
        );
        assert!(SecurityCouncil::from_str(&input).is_err());

        // Test empty public keys
        assert!(SecurityCouncil::from_str("2:").is_err());
    }

    #[test]
    fn test_security_council_round_trip() {
        // Create some test public keys
        let pk1 = XOnlyPublicKey::from_slice(&[1; 32]).unwrap();
        let pk2 = XOnlyPublicKey::from_slice(&[2; 32]).unwrap();

        let original = SecurityCouncil {
            pks: vec![pk1, pk2],
            threshold: 2,
        };

        let string = original.to_string();
        let parsed = SecurityCouncil::from_str(&string).unwrap();

        assert_eq!(original, parsed);
    }
}
