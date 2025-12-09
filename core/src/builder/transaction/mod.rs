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
//! - [`mod.rs`] - The main entry point, re-exporting key types and functions. Defines some helper functions for creating taproot outputs.
//! - [`creator.rs`] - Contains the functions to create multiple TxHandler's for a deposit and related structs for caching. In particular, it contains the functions to create TxHandler's for all transactions generated during a deposit from a single kickoff.
//! - [`operator_collateral.rs`] - Handles the creation of operator-specific collateral-related transactions, such as round, ready-to-reimburse, and unspent kickoff transactions.
//! - [`operator_reimburse.rs`] - Implements the creation of reimbursement and payout transactions, including logic for operator compensation and optimistic payouts.
//! - [`operator_assert.rs`] - Provides functions for creating BitVM assertion and timeout transactions.
//! - [`challenge.rs`] - Handles the creation of challenge, disprove, and watchtower challenge transactions, supporting protocol dispute resolution and fraud proofs.
//! - [`sign.rs`] - Contains logic for signing transactions using data in the [`TxHandler`].
//! - [`txhandler.rs`] - Defines the [`TxHandler`] abstraction, which wraps a transaction and its metadata, and provides methods for signing, finalizing, and extracting transaction data.
//! - [`input.rs`] - Defines types and utilities for transaction inputs used in the [`TxHandler`].
//! - [`output.rs`] - Defines types and utilities for transaction outputs used in the [`TxHandler`].
//! - [`deposit_signature_owner.rs`] - Maps which TxIn signatures are signed by which protocol entities, additionally supporting different Sighash types.
//!

use super::script::{CheckSig, Multisig, SpendableScript};
use super::script::{ReplacementDepositScript, SpendPath};
use crate::builder::address::calculate_taproot_leaf_depths;
use crate::builder::script::OtherSpendable;
use crate::builder::transaction::challenge::*;
use crate::builder::transaction::input::SpendableTxIn;
use crate::builder::transaction::operator_assert::*;
use crate::builder::transaction::operator_collateral::*;
use crate::builder::transaction::operator_reimburse::*;
use crate::builder::transaction::output::UnspentTxOut;
use crate::config::protocol::ProtocolParamset;
use crate::constants::{NON_EPHEMERAL_ANCHOR_AMOUNT, NON_STANDARD_V3};
use crate::deposit::{DepositData, SecurityCouncil};
use crate::errors::BridgeError;
use crate::operator::RoundIndex;
use crate::rpc::clementine::grpc_transaction_id;
use crate::rpc::clementine::GrpcTransactionId;
use crate::rpc::clementine::{
    NormalSignatureKind, NormalTransactionId, NumberedTransactionId, NumberedTransactionType,
};
use bitcoin::hashes::Hash;
use bitcoin::opcodes::all::OP_RETURN;
use bitcoin::script::Builder;
use bitcoin::transaction::Version;
use bitcoin::{Address, Amount, OutPoint, ScriptBuf, Transaction, TxOut, Txid, XOnlyPublicKey};
use hex;
use input::UtxoVout;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;

// Exports to the outside
pub use crate::builder::transaction::txhandler::*;
pub use creator::{
    create_round_txhandlers, create_txhandlers, ContractContext, KickoffWinternitzKeys,
    ReimburseDbCache, TxHandlerCache,
};
pub use operator_collateral::{
    create_burn_unused_kickoff_connectors_txhandler, create_round_nth_txhandler,
};
pub use operator_reimburse::{create_optimistic_payout_txhandler, create_payout_txhandler};
pub use txhandler::Unsigned;

pub mod challenge;
mod creator;
pub mod deposit_signature_owner;
pub mod input;
mod operator_assert;
mod operator_collateral;
mod operator_reimburse;
pub mod output;
pub mod sign;
mod txhandler;

type HiddenNode<'a> = &'a [u8; 32];

#[derive(Debug, Error)]
pub enum TxError {
    /// TxInputNotFound is returned when the input is not found in the transaction
    #[error("Could not find input of transaction")]
    TxInputNotFound,
    #[error("Could not find output of transaction")]
    TxOutputNotFound,
    #[error("Attempted to set witness when it's already set")]
    WitnessAlreadySet,
    #[error("Script with index {0} not found for transaction")]
    ScriptNotFound(usize),
    #[error("Insufficient Context data for the requested TxHandler")]
    InsufficientContext,
    #[error("No scripts in TxHandler for the TxIn with index {0}")]
    NoScriptsForTxIn(usize),
    #[error("No script in TxHandler for the index {0}")]
    NoScriptAtIndex(usize),
    #[error("Spend Path in SpentTxIn in TxHandler not specified")]
    SpendPathNotSpecified,
    #[error("Actor does not own the key needed in P2TR keypath")]
    NotOwnKeyPath,
    #[error("public key of Checksig in script is not owned by Actor")]
    NotOwnedScriptPath,
    #[error("Couldn't find needed signature from database for tx: {:?}", _0)]
    SignatureNotFound(TransactionType),
    #[error("Couldn't find needed txhandler during creation for tx: {:?}", _0)]
    TxHandlerNotFound(TransactionType),
    #[error("BitvmSetupNotFound for operator {0:?}, deposit_txid {1}")]
    BitvmSetupNotFound(XOnlyPublicKey, Txid),
    #[error("Transaction input is missing spend info")]
    MissingSpendInfo,
    #[error("Incorrect watchtower challenge data length")]
    IncorrectWatchtowerChallengeDataLength,
    #[error("Latest blockhash script must be a single script")]
    LatestBlockhashScriptNumber,
    #[error("Round index cannot be used to create a Round transaction: {0:?}")]
    InvalidRoundIndex(RoundIndex),
    #[error("Index overflow")]
    IndexOverflow,
    #[error("Kickoff winternitz keys in DB has wrong size compared to paramset")]
    KickoffWinternitzKeysDBInconsistency,

    #[error(transparent)]
    Other(#[from] eyre::Report),
}

/// Types of all transactions that can be created. Some transactions have a
/// (usize) index as there are multiple instances of the same transaction type
/// per kickoff.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum TransactionType {
    // --- Transaction Types ---
    AssertTimeout(usize),
    BurnUnusedKickoffConnectors,
    Challenge,
    ChallengeTimeout,
    Disprove,
    DisproveTimeout,
    EmergencyStop,
    Kickoff,
    KickoffNotFinalized,
    LatestBlockhash,
    LatestBlockhashTimeout,
    MiniAssert(usize),
    MoveToVault,
    OperatorChallengeAck(usize),
    OperatorChallengeNack(usize),
    OptimisticPayout,
    Payout,
    ReadyToReimburse,
    Reimburse,
    ReplacementDeposit,
    Round,
    UnspentKickoff(usize),
    WatchtowerChallenge(usize),
    WatchtowerChallengeTimeout(usize),

    // --- Transaction Subsets ---
    AllNeededForDeposit, // this will include all tx's that is to be signed for a deposit for verifiers
    YieldKickoffTxid, // This is just to yield kickoff txid from the sighash stream, not used for anything else, sorry

    /// For testing and for values to be replaced later.
    Dummy,
}

// converter from proto type to rust enum
impl TryFrom<GrpcTransactionId> for TransactionType {
    type Error = ::prost::UnknownEnumValue;
    fn try_from(value: GrpcTransactionId) -> Result<Self, Self::Error> {
        use NormalTransactionId as Normal;
        use NumberedTransactionType as Numbered;
        // return err if id is None
        let inner_id = value.id.ok_or(::prost::UnknownEnumValue(0))?;
        match inner_id {
            grpc_transaction_id::Id::NormalTransaction(idx) => {
                let tx_type = NormalTransactionId::try_from(idx)?;
                match tx_type {
                    Normal::Round => Ok(Self::Round),
                    Normal::Kickoff => Ok(Self::Kickoff),
                    Normal::MoveToVault => Ok(Self::MoveToVault),
                    Normal::Payout => Ok(Self::Payout),
                    Normal::Challenge => Ok(Self::Challenge),
                    Normal::Disprove => Ok(Self::Disprove),
                    Normal::DisproveTimeout => Ok(Self::DisproveTimeout),
                    Normal::Reimburse => Ok(Self::Reimburse),
                    Normal::AllNeededForDeposit => Ok(Self::AllNeededForDeposit),
                    Normal::Dummy => Ok(Self::Dummy),
                    Normal::ReadyToReimburse => Ok(Self::ReadyToReimburse),
                    Normal::KickoffNotFinalized => Ok(Self::KickoffNotFinalized),
                    Normal::ChallengeTimeout => Ok(Self::ChallengeTimeout),
                    Normal::UnspecifiedTransactionType => Err(::prost::UnknownEnumValue(idx)),
                    Normal::BurnUnusedKickoffConnectors => Ok(Self::BurnUnusedKickoffConnectors),
                    Normal::YieldKickoffTxid => Ok(Self::YieldKickoffTxid),
                    Normal::ReplacementDeposit => Ok(Self::ReplacementDeposit),
                    Normal::LatestBlockhashTimeout => Ok(Self::LatestBlockhashTimeout),
                    Normal::LatestBlockhash => Ok(Self::LatestBlockhash),
                    Normal::OptimisticPayout => Ok(Self::OptimisticPayout),
                }
            }
            grpc_transaction_id::Id::NumberedTransaction(transaction_id) => {
                let tx_type = NumberedTransactionType::try_from(transaction_id.transaction_type)?;
                match tx_type {
                    Numbered::WatchtowerChallenge => {
                        Ok(Self::WatchtowerChallenge(transaction_id.index as usize))
                    }
                    Numbered::OperatorChallengeNack => {
                        Ok(Self::OperatorChallengeNack(transaction_id.index as usize))
                    }
                    Numbered::OperatorChallengeAck => {
                        Ok(Self::OperatorChallengeAck(transaction_id.index as usize))
                    }
                    Numbered::AssertTimeout => {
                        Ok(Self::AssertTimeout(transaction_id.index as usize))
                    }
                    Numbered::UnspentKickoff => {
                        Ok(Self::UnspentKickoff(transaction_id.index as usize))
                    }
                    Numbered::MiniAssert => Ok(Self::MiniAssert(transaction_id.index as usize)),
                    Numbered::WatchtowerChallengeTimeout => Ok(Self::WatchtowerChallengeTimeout(
                        transaction_id.index as usize,
                    )),
                    Numbered::UnspecifiedIndexedTransactionType => {
                        Err(::prost::UnknownEnumValue(transaction_id.transaction_type))
                    }
                }
            }
        }
    }
}

impl From<TransactionType> for GrpcTransactionId {
    fn from(value: TransactionType) -> Self {
        use grpc_transaction_id::Id::*;
        use NormalTransactionId as Normal;
        use NumberedTransactionType as Numbered;
        GrpcTransactionId {
            id: Some(match value {
                TransactionType::Round => NormalTransaction(Normal::Round as i32),
                TransactionType::Kickoff => NormalTransaction(Normal::Kickoff as i32),
                TransactionType::MoveToVault => NormalTransaction(Normal::MoveToVault as i32),
                TransactionType::Payout => NormalTransaction(Normal::Payout as i32),
                TransactionType::Challenge => NormalTransaction(Normal::Challenge as i32),
                TransactionType::Disprove => NormalTransaction(Normal::Disprove as i32),
                TransactionType::DisproveTimeout => {
                    NormalTransaction(Normal::DisproveTimeout as i32)
                }
                TransactionType::Reimburse => NormalTransaction(Normal::Reimburse as i32),
                TransactionType::AllNeededForDeposit => {
                    NormalTransaction(Normal::AllNeededForDeposit as i32)
                }
                TransactionType::Dummy => NormalTransaction(Normal::Dummy as i32),
                TransactionType::ReadyToReimburse => {
                    NormalTransaction(Normal::ReadyToReimburse as i32)
                }
                TransactionType::KickoffNotFinalized => {
                    NormalTransaction(Normal::KickoffNotFinalized as i32)
                }
                TransactionType::ChallengeTimeout => {
                    NormalTransaction(Normal::ChallengeTimeout as i32)
                }
                TransactionType::ReplacementDeposit => {
                    NormalTransaction(Normal::ReplacementDeposit as i32)
                }
                TransactionType::LatestBlockhashTimeout => {
                    NormalTransaction(Normal::LatestBlockhashTimeout as i32)
                }
                TransactionType::LatestBlockhash => {
                    NormalTransaction(Normal::LatestBlockhash as i32)
                }
                TransactionType::OptimisticPayout => {
                    NormalTransaction(Normal::OptimisticPayout as i32)
                }
                TransactionType::WatchtowerChallenge(index) => {
                    NumberedTransaction(NumberedTransactionId {
                        transaction_type: Numbered::WatchtowerChallenge as i32,
                        index: index as i32,
                    })
                }
                TransactionType::OperatorChallengeNack(index) => {
                    NumberedTransaction(NumberedTransactionId {
                        transaction_type: Numbered::OperatorChallengeNack as i32,
                        index: index as i32,
                    })
                }
                TransactionType::OperatorChallengeAck(index) => {
                    NumberedTransaction(NumberedTransactionId {
                        transaction_type: Numbered::OperatorChallengeAck as i32,
                        index: index as i32,
                    })
                }
                TransactionType::AssertTimeout(index) => {
                    NumberedTransaction(NumberedTransactionId {
                        transaction_type: Numbered::AssertTimeout as i32,
                        index: index as i32,
                    })
                }
                TransactionType::UnspentKickoff(index) => {
                    NumberedTransaction(NumberedTransactionId {
                        transaction_type: Numbered::UnspentKickoff as i32,
                        index: index as i32,
                    })
                }
                TransactionType::MiniAssert(index) => NumberedTransaction(NumberedTransactionId {
                    transaction_type: Numbered::MiniAssert as i32,
                    index: index as i32,
                }),
                TransactionType::WatchtowerChallengeTimeout(index) => {
                    NumberedTransaction(NumberedTransactionId {
                        transaction_type: Numbered::WatchtowerChallengeTimeout as i32,
                        index: index as i32,
                    })
                }
                TransactionType::BurnUnusedKickoffConnectors => {
                    NormalTransaction(Normal::BurnUnusedKickoffConnectors as i32)
                }
                TransactionType::YieldKickoffTxid => {
                    NormalTransaction(Normal::YieldKickoffTxid as i32)
                }
                TransactionType::EmergencyStop => {
                    NormalTransaction(Normal::UnspecifiedTransactionType as i32)
                }
            }),
        }
    }
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
///
/// # Warning
///
/// Does not check if the data is valid for an OP_RETURN script. Data must be at most 80 bytes.
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

/// Creates a [`TxHandler`] for the `move_to_vault_tx`.
///
/// This transaction moves funds to a N-of-N address from the deposit address created by the user that deposits into Citrea after all signature collection operations are done for the deposit.
///
/// # Arguments
///
/// * `deposit_data` - Mutable reference to the deposit data for the transaction.
/// * `paramset` - Protocol parameter set.
///
/// # Returns
///
/// A [`TxHandler`] for the move-to-vault transaction, or a [`BridgeError`] if construction fails.
pub fn create_move_to_vault_txhandler(
    deposit_data: &mut DepositData,
    paramset: &'static ProtocolParamset,
) -> Result<TxHandler<Unsigned>, BridgeError> {
    let nofn_xonly_pk = deposit_data.get_nofn_xonly_pk()?;
    let deposit_outpoint = deposit_data.get_deposit_outpoint();
    let nofn_script = Arc::new(CheckSig::new(nofn_xonly_pk));
    let security_council_script = Arc::new(Multisig::from_security_council(
        deposit_data.security_council.clone(),
    ));

    let deposit_scripts = deposit_data.get_deposit_scripts(paramset)?;

    Ok(TxHandlerBuilder::new(TransactionType::MoveToVault)
        .with_version(NON_STANDARD_V3)
        .add_input(
            NormalSignatureKind::NotStored,
            SpendableTxIn::from_scripts(
                deposit_outpoint,
                paramset.bridge_amount,
                deposit_scripts,
                None,
                paramset.network,
            ),
            SpendPath::ScriptSpend(0),
            DEFAULT_SEQUENCE,
        )
        .add_output(UnspentTxOut::from_scripts(
            paramset.bridge_amount,
            vec![nofn_script, security_council_script],
            None,
            paramset.network,
        ))
        // always use 0 sat anchor for move_tx, this will keep the amount in move to vault tx exactly the bridge amount
        .add_output(UnspentTxOut::from_partial(anchor_output(Amount::from_sat(
            0,
        ))))
        .finalize())
}

/// Creates a [`TxHandler`] for the `emergency_stop_tx`.
///
/// This transaction moves funds to the address controlled by the security council from the move-to-vault txout.
/// Used to stop the deposit in case of a security issue. The moved funds will eventually be redeposited using the replacement deposit tx.
///
/// # Arguments
///
/// * `deposit_data` - Mutable reference to the deposit data for the transaction.
/// * `move_to_vault_txhandler` - Reference to the move-to-vault transaction handler.
/// * `paramset` - Protocol parameter set.
///
/// # Returns
///
/// A [`TxHandler`] for the emergency stop transaction, or a [`BridgeError`] if construction fails.
pub fn create_emergency_stop_txhandler(
    deposit_data: &mut DepositData,
    move_to_vault_txhandler: &TxHandler,
    paramset: &'static ProtocolParamset,
) -> Result<TxHandler<Unsigned>, BridgeError> {
    // Hand calculated, total tx size is 11 + 126 * NUM_EMERGENCY_STOPS
    const EACH_EMERGENCY_STOP_VBYTES: Amount = Amount::from_sat(126);
    let security_council = deposit_data.security_council.clone();

    let builder = TxHandlerBuilder::new(TransactionType::EmergencyStop)
        .add_input(
            NormalSignatureKind::NotStored,
            move_to_vault_txhandler.get_spendable_output(UtxoVout::DepositInMove)?,
            SpendPath::ScriptSpend(0),
            DEFAULT_SEQUENCE,
        )
        .add_output(UnspentTxOut::from_scripts(
            paramset.bridge_amount - paramset.anchor_amount() - EACH_EMERGENCY_STOP_VBYTES * 3,
            vec![Arc::new(Multisig::from_security_council(security_council))],
            None,
            paramset.network,
        ))
        .finalize();

    Ok(builder)
}

/// Creates a [`TxHandler`] for the `replacement_deposit_tx`.
///
/// This transaction replaces a previous deposit with a new deposit.
/// In the its script, it commits the old move_to_vault txid that it replaces.
///
/// # Arguments
///
/// * `old_move_txid` - The txid of the old move_to_vault transaction that is being replaced.
/// * `input_outpoint` - The outpoint of the input to the replacement deposit tx that holds bridge amount.
/// * `nofn_xonly_pk` - The N-of-N XOnlyPublicKey for the deposit.
/// * `paramset` - The protocol paramset.
/// * `security_council` - The security council.
///
/// # Returns
///
/// A [`TxHandler`] for the replacement deposit transaction, or a [`BridgeError`] if construction fails.
#[cfg(test)]
pub fn create_replacement_deposit_txhandler(
    old_move_txid: Txid,
    input_outpoint: OutPoint,
    old_nofn_xonly_pk: XOnlyPublicKey,
    new_nofn_xonly_pk: XOnlyPublicKey,
    paramset: &'static ProtocolParamset,
    security_council: SecurityCouncil,
) -> Result<TxHandler, BridgeError> {
    Ok(TxHandlerBuilder::new(TransactionType::ReplacementDeposit)
        .with_version(NON_STANDARD_V3)
        .add_input(
            NormalSignatureKind::NoSignature,
            SpendableTxIn::from_scripts(
                input_outpoint,
                paramset.bridge_amount,
                vec![
                    Arc::new(CheckSig::new(old_nofn_xonly_pk)),
                    Arc::new(Multisig::from_security_council(security_council.clone())),
                ],
                None,
                paramset.network,
            ),
            crate::builder::script::SpendPath::ScriptSpend(0),
            DEFAULT_SEQUENCE,
        )
        .add_output(UnspentTxOut::from_scripts(
            paramset.bridge_amount,
            vec![
                Arc::new(ReplacementDepositScript::new(
                    new_nofn_xonly_pk,
                    old_move_txid,
                )),
                Arc::new(Multisig::from_security_council(security_council)),
            ],
            None,
            paramset.network,
        ))
        // always use 0 sat anchor for replacement deposit tx, this will keep the amount in replacement deposit tx exactly the bridge amount
        .add_output(UnspentTxOut::from_partial(anchor_output(Amount::from_sat(
            0,
        ))))
        .finalize())
}

/// Creates a Taproot output for a disprove path, combining a script, an additional disprove script, and a hidden node containing the BitVM disprove scripts.
///
/// # Arguments
///
/// * `operator_timeout_script` - The operator timeout script.
/// * `additional_script` - An additional script to include in the Taproot tree. This single additional script is generated by Clementine bridge in addition to the disprove scripts coming from BitVM side.
/// * `disprove_root_hash` - The root hash for the hidden script merkle tree node. The scripts included in the root hash are the BitVM disprove scripts.
/// * `amount` - The output amount.
/// * `network` - The Bitcoin network.
///
/// # Returns
///
/// An [`UnspentTxOut`] representing the Taproot TxOut.
pub fn create_disprove_taproot_output(
    operator_timeout_script: Arc<dyn SpendableScript>,
    additional_script: ScriptBuf,
    disprove_path: DisprovePath,
    amount: Amount,
    network: bitcoin::Network,
) -> UnspentTxOut {
    use crate::bitvm_client::{SECP, UNSPENDABLE_XONLY_PUBKEY};
    use bitcoin::taproot::{TapNodeHash, TaprootBuilder};

    let mut scripts: Vec<ScriptBuf> = vec![additional_script.clone()];

    let builder = match disprove_path.clone() {
        DisprovePath::Scripts(extra_scripts) => {
            let mut builder = TaprootBuilder::new();

            builder = builder
                .add_leaf(1, operator_timeout_script.to_script_buf())
                .expect("add operator timeout script")
                .add_leaf(2, additional_script)
                .expect("add additional script");

            // 1. Calculate depths. This is cheap and doesn't need ownership of scripts.
            let depths = calculate_taproot_leaf_depths(extra_scripts.len());

            // 2. Zip depths with an iterator over the scripts.
            //    We clone the `script` inside the loop because the builder needs an owned value.
            //    This is more efficient than cloning the whole Vec upfront.
            for (depth, script) in depths.into_iter().zip(extra_scripts.iter()) {
                let main_tree_depth = 2 + depth;
                builder = builder
                    .add_leaf(main_tree_depth, script.clone())
                    .expect("add inlined disprove script");
            }

            // 3. Now, move the original `extra_scripts` into `scripts.extend`. No clone needed.
            scripts.extend(extra_scripts);
            builder
        }
        DisprovePath::HiddenNode(root_hash) => TaprootBuilder::new()
            .add_leaf(1, operator_timeout_script.to_script_buf())
            .expect("empty taptree will accept a script node")
            .add_leaf(2, additional_script)
            .expect("taptree with one node will accept a node at depth 2")
            .add_hidden_node(2, TapNodeHash::from_byte_array(*root_hash))
            .expect("taptree with two nodes will accept a node at depth 2"),
    };

    let taproot_spend_info = builder
        .finalize(&SECP, *UNSPENDABLE_XONLY_PUBKEY)
        .expect("valid taptree");

    let address = Address::p2tr(
        &SECP,
        *UNSPENDABLE_XONLY_PUBKEY,
        taproot_spend_info.merkle_root(),
        network,
    );

    let mut spendable_scripts: Vec<Arc<dyn SpendableScript>> = vec![operator_timeout_script];
    let other_spendable_scripts: Vec<Arc<dyn SpendableScript>> = scripts
        .into_iter()
        .map(|script| Arc::new(OtherSpendable::new(script)) as Arc<dyn SpendableScript>)
        .collect();

    spendable_scripts.extend(other_spendable_scripts);

    UnspentTxOut::new(
        TxOut {
            value: amount,
            script_pubkey: address.script_pubkey(),
        },
        spendable_scripts,
        Some(taproot_spend_info),
    )
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
    script: Arc<dyn SpendableScript>,
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

    UnspentTxOut::new(
        TxOut {
            value: amount,
            script_pubkey: address.script_pubkey(),
        },
        vec![script.clone()],
        Some(taproot_spend_info),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
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
