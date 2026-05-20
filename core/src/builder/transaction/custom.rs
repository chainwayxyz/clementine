//! Reusable non-protocol tx-builder spec for local/runtime transactions.
//!
//! We need this because some transactions in the tree are buildable/signable with the
//! generic `tx-builder` machinery, but they are not part of the Clementine protocol
//! vocabulary and should not be added to `TransactionType` / protocol ids just
//! to get typed inputs, outputs, and leaves.
//!
//! Typical uses:
//! - operator-local wallet transfers
//! - tests that needed custom tx's that supported signing

use crate::actor::Actor;
use bitcoin::{OutPoint, Transaction};
use clementine_errors::BridgeError;
use tx_builder::input::SpendableTxIn;
use tx_builder::output::UnspentTxOut;
use tx_builder::script::{ScriptLeaf, ScriptNode};
use tx_builder::spec::SpendSpec;
use tx_builder::txhandler::{TxHandler, TxHandlerBuilder};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CustomTx {
    Custom(usize),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CustomInput {
    Custom(usize),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CustomLeaf {
    Custom(usize, usize),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CustomActor {
    Custom(usize),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CustomOutput {
    Custom(usize),
}

pub type CustomTxHandler = TxHandler<CustomTx, CustomInput, CustomOutput, CustomLeaf, CustomActor>;
pub type CustomTxHandlerBuilder =
    TxHandlerBuilder<CustomTx, CustomInput, CustomOutput, CustomLeaf, CustomActor>;
pub type CustomSpendableTxIn = SpendableTxIn<CustomLeaf>;
pub type CustomUnspentTxOut = UnspentTxOut<CustomLeaf>;

pub fn tx(id: usize) -> CustomTx {
    CustomTx::Custom(id)
}

pub fn input(id: usize) -> CustomInput {
    CustomInput::Custom(id)
}

pub fn output(id: usize) -> CustomOutput {
    CustomOutput::Custom(id)
}

pub fn leaf(input_idx: usize, script_idx: usize) -> CustomLeaf {
    CustomLeaf::Custom(input_idx, script_idx)
}

pub fn builder(tx_idx: usize) -> CustomTxHandlerBuilder {
    CustomTxHandlerBuilder::new(tx(tx_idx))
}

pub fn descriptor(
    spend: SpendSpec<CustomLeaf, CustomActor>,
    sighash_type: bitcoin::TapSighashType,
) -> SpendSpec<CustomLeaf, CustomActor> {
    spend.with_metadata(None, Some(sighash_type))
}

pub fn key_spend_descriptor(
    sighash_type: bitcoin::TapSighashType,
) -> SpendSpec<CustomLeaf, CustomActor> {
    descriptor(SpendSpec::key_spend(), sighash_type)
}

pub fn named_leaf_descriptor(
    input_idx: usize,
    script_idx: usize,
    sighash_type: bitcoin::TapSighashType,
) -> SpendSpec<CustomLeaf, CustomActor> {
    descriptor(
        SpendSpec::named_leaf(leaf(input_idx, script_idx)),
        sighash_type,
    )
}

pub fn spendable_from_script_leaves(
    input_idx: usize,
    previous_output: OutPoint,
    prevout_value: bitcoin::Amount,
    scripts: Vec<ScriptLeaf>,
    internal_key: Option<bitcoin::XOnlyPublicKey>,
    network: bitcoin::Network,
) -> CustomSpendableTxIn {
    let script_nodes = scripts
        .iter()
        .cloned()
        .map(ScriptNode::Leaf)
        .collect::<Vec<_>>();
    let named_leaves = scripts
        .into_iter()
        .enumerate()
        .map(|(script_idx, script)| (leaf(input_idx, script_idx), script))
        .collect::<Vec<_>>();
    let output = UnspentTxOut::from_scripts(prevout_value, script_nodes, internal_key, network)
        .with_named_leaves(named_leaves);

    SpendableTxIn::from_output(previous_output, &output)
}

pub fn output_from_script_leaves(
    output_idx: usize,
    amount: bitcoin::Amount,
    scripts: Vec<ScriptLeaf>,
    internal_key: Option<bitcoin::XOnlyPublicKey>,
    network: bitcoin::Network,
) -> (CustomOutput, CustomUnspentTxOut) {
    let script_nodes = scripts
        .into_iter()
        .map(ScriptNode::Leaf)
        .collect::<Vec<_>>();
    (
        output(output_idx),
        UnspentTxOut::from_scripts(amount, script_nodes, internal_key, network),
    )
}

pub fn sign_with_actor(actor: &Actor, txhandler: &mut CustomTxHandler) -> Result<(), BridgeError> {
    actor.sign_schnorr(txhandler, None)
}

pub fn current_tx(txhandler: &CustomTxHandler) -> &Transaction {
    txhandler.transaction()
}

pub fn spendable_output(
    txhandler: &CustomTxHandler,
    output_idx: usize,
) -> Result<CustomSpendableTxIn, BridgeError> {
    txhandler.get_spendable_output(output(output_idx))
}
