//! # Collaterals
//!
//! This module contains the logic for creating the `round_tx`, `ready_to_reimburse_tx`,
//! and `unspent_kickoff_tx` transactions. These transactions are used to control the sequence of transactions
//! in the withdrawal process and limits the number of withdrawals the operator can make in a given time period.
//!
//! The flow is as follows:
//! `round_tx -> ready_to_reimburse_tx -> round_tx -> ...`
//!
//! The `round_tx` is used to create a collateral for the withdrawal, kickoff utxos for the current
//! round and the reimburse connectors for the previous round.

use super::input::UtxoVout;
use super::txhandler::DEFAULT_SEQUENCE;
use crate::builder;
use crate::builder::address::create_taproot_address;
use crate::builder::script::{TimelockScript, WinternitzCommit};
use crate::builder::transaction::creator::KickoffWinternitzKeys;
use crate::builder::transaction::input::SpendableTxIn;
use crate::builder::transaction::output::UnspentTxOut;
use crate::builder::transaction::txhandler::TxHandler;
use crate::builder::transaction::*;
use crate::config::protocol::ProtocolParamset;
use crate::constants::MIN_TAPROOT_AMOUNT;
use crate::errors::BridgeError;
use crate::rpc::clementine::NumberedSignatureKind;
use bitcoin::Sequence;
use bitcoin::{Amount, OutPoint, TxOut, XOnlyPublicKey};
use std::sync::Arc;

pub enum RoundTxInput {
    Prevout(Box<SpendableTxIn>),
    Collateral(OutPoint, Amount),
}

/// Creates a [`TxHandler`] for `round_tx`.
///
/// This transaction is used to create a collateral for the withdrawal, kickoff UTXOs for the current round, and the reimburse connectors for the previous round.
/// It always uses the first output of the previous `ready_to_reimburse_tx` as the input, chaining rounds together.
///
/// `round tx` inputs:
/// 1. Either the first collateral utxo of operator, or operators collateral in the previous rounds ready to reimburse tx.
///
/// `round tx` outputs:
/// 1. Operator's Burn Connector
/// 2. Kickoff utxo(s): the utxos will be used as the input for the kickoff transactions
/// 3. Reimburse utxo(s): the utxo(s) will be used as an input to Reimburse TX
/// 4. P2Anchor: Anchor output for CPFP
///
/// # Arguments
/// * `operator_xonly_pk` - The operator's x-only public key.
/// * `txin` - The input to the round transaction (either a previous output or the first collateral).
/// * `pubkeys` - Winternitz public keys for the round's kickoff UTXOs.
/// * `paramset` - Protocol parameter set.
///
/// # Returns
/// A [`TxHandler`] for the round transaction, or a [`BridgeError`] if construction fails.
pub fn create_round_txhandler(
    operator_xonly_pk: XOnlyPublicKey,
    txin: RoundTxInput,
    pubkeys: &[bitvm::signatures::winternitz::PublicKey],
    paramset: &'static ProtocolParamset,
) -> Result<TxHandler, BridgeError> {
    let mut builder = TxHandlerBuilder::new(TransactionType::Round).with_version(NON_STANDARD_V3);
    let input_amount;
    match txin {
        RoundTxInput::Prevout(prevout) => {
            input_amount = prevout.get_prevout().value;
            builder = builder.add_input(
                NormalSignatureKind::OperatorSighashDefault,
                *prevout,
                SpendPath::KeySpend,
                Sequence::from_height(paramset.operator_reimburse_timelock),
            );
        }
        RoundTxInput::Collateral(outpoint, amount) => {
            let (op_address, op_spend) =
                create_taproot_address(&[], Some(operator_xonly_pk), paramset.network);
            input_amount = amount;
            builder = builder.add_input(
                NormalSignatureKind::OperatorSighashDefault,
                SpendableTxIn::new(
                    outpoint,
                    TxOut {
                        value: input_amount,
                        script_pubkey: op_address.script_pubkey(),
                    },
                    vec![],
                    Some(op_spend.clone()),
                ),
                SpendPath::KeySpend,
                DEFAULT_SEQUENCE,
            );
        }
    }

    // This 1 block is to enforce that operator has to put a sequence number in the input
    // so this spending path can't be used to send kickoff tx
    let timeout_block_count_locked_script =
        Arc::new(TimelockScript::new(Some(operator_xonly_pk), 1));

    let total_required = (paramset.kickoff_amount + paramset.default_utxo_amount())
        .checked_mul(paramset.num_kickoffs_per_round as u64)
        .and_then(|kickoff_total| kickoff_total.checked_add(paramset.anchor_amount()))
        .ok_or_else(|| {
            BridgeError::ArithmeticOverflow("Total required amount calculation overflow")
        })?;

    let remaining_amount = input_amount.checked_sub(total_required).ok_or_else(|| {
        BridgeError::InsufficientFunds("Input amount insufficient for required outputs")
    })?;

    builder = builder.add_output(UnspentTxOut::from_scripts(
        remaining_amount,
        vec![],
        Some(operator_xonly_pk),
        paramset.network,
    ));

    // add kickoff utxos
    for pubkey in pubkeys.iter().take(paramset.num_kickoffs_per_round) {
        let blockhash_commit = Arc::new(WinternitzCommit::new(
            vec![(pubkey.clone(), paramset.kickoff_blockhash_commit_length)],
            operator_xonly_pk,
            paramset.winternitz_log_d,
        ));
        builder = builder.add_output(UnspentTxOut::from_scripts(
            paramset.kickoff_amount,
            vec![blockhash_commit, timeout_block_count_locked_script.clone()],
            None,
            paramset.network,
        ));
    }
    // Create reimburse utxos
    for _ in 0..paramset.num_kickoffs_per_round {
        builder = builder.add_output(UnspentTxOut::from_scripts(
            paramset.default_utxo_amount(),
            vec![],
            Some(operator_xonly_pk),
            paramset.network,
        ));
    }
    Ok(builder
        .add_output(UnspentTxOut::from_partial(
            builder::transaction::anchor_output(paramset.anchor_amount()),
        ))
        .finalize())
}

/// Creates a vector of [`TxHandler`] for `assert_timeout_tx` transactions.
///
/// These transactions can be sent by anyone if the operator did not send their asserts in time, burning their burn connector and kickoff finalizer.
///
/// # Inputs
/// 1. KickoffTx: Assert utxo (corresponding to the assert)
/// 2. KickoffTx: KickoffFinalizer utxo
/// 3. RoundTx: BurnConnector utxo
///
/// # Outputs
/// 1. Anchor output for CPFP
///
/// # Arguments
/// * `kickoff_txhandler` - The kickoff transaction handler providing the input.
/// * `round_txhandler` - The round transaction handler providing an additional input.
/// * `num_asserts` - Number of assert timeout transactions to create.
/// * `paramset` - Protocol parameter set.
///
/// # Returns
/// A vector of [`TxHandler`] for all assert timeout transactions, or a [`BridgeError`] if construction fails.
pub fn create_assert_timeout_txhandlers(
    kickoff_txhandler: &TxHandler,
    round_txhandler: &TxHandler,
    num_asserts: usize,
    paramset: &'static ProtocolParamset,
) -> Result<Vec<TxHandler>, BridgeError> {
    let mut txhandlers = Vec::new();
    for idx in 0..num_asserts {
        txhandlers.push(
            TxHandlerBuilder::new(TransactionType::AssertTimeout(idx))
                .with_version(NON_STANDARD_V3)
                .add_input(
                    (NumberedSignatureKind::AssertTimeout1, idx as i32),
                    kickoff_txhandler.get_spendable_output(UtxoVout::Assert(idx))?,
                    SpendPath::ScriptSpend(0),
                    Sequence::from_height(paramset.assert_timeout_timelock),
                )
                .add_input(
                    (NumberedSignatureKind::AssertTimeout2, idx as i32),
                    kickoff_txhandler.get_spendable_output(UtxoVout::KickoffFinalizer)?,
                    SpendPath::ScriptSpend(0),
                    DEFAULT_SEQUENCE,
                )
                .add_input(
                    (NumberedSignatureKind::AssertTimeout3, idx as i32),
                    round_txhandler.get_spendable_output(UtxoVout::CollateralInRound)?,
                    SpendPath::KeySpend,
                    DEFAULT_SEQUENCE,
                )
                .add_output(UnspentTxOut::from_partial(
                    builder::transaction::anchor_output(paramset.anchor_amount()),
                ))
                .finalize(),
        );
    }
    Ok(txhandlers)
}

/// Creates the nth (1-indexed) `round_txhandler` and `reimburse_generator_txhandler` pair for a specific operator.
///
/// # Arguments
/// * `operator_xonly_pk` - The operator's x-only public key.
/// * `input_outpoint` - The outpoint to use as input for the first round.
/// * `input_amount` - The amount for the input outpoint.
/// * `index` - The index of the round to create.
/// * `pubkeys` - Winternitz keys for all rounds.
/// * `paramset` - Protocol parameter set.
///
/// # Returns
/// A tuple of (`TxHandler` for the round, `TxHandler` for ready-to-reimburse), or a [`BridgeError`] if construction fails.
pub fn create_round_nth_txhandler(
    operator_xonly_pk: XOnlyPublicKey,
    input_outpoint: OutPoint,
    input_amount: Amount,
    index: RoundIndex,
    pubkeys: &KickoffWinternitzKeys,
    paramset: &'static ProtocolParamset,
) -> Result<(TxHandler, TxHandler), BridgeError> {
    // 0th round is the collateral, there are no keys for the 0th round
    // Additionally there are no keys after num_rounds + 1, +1 is because we need additional round to generate
    // reimbursement connectors of previous round

    if index == RoundIndex::Collateral
        || index.to_index() > RoundIndex::Round(paramset.num_round_txs).to_index()
    {
        return Err(TxError::InvalidRoundIndex(index).into());
    }

    // create the first round txhandler
    let mut round_txhandler = create_round_txhandler(
        operator_xonly_pk,
        RoundTxInput::Collateral(input_outpoint, input_amount),
        pubkeys.get_keys_for_round(RoundIndex::Round(0))?,
        paramset,
    )?;
    let mut ready_to_reimburse_txhandler =
        create_ready_to_reimburse_txhandler(&round_txhandler, operator_xonly_pk, paramset)?;

    // get which round index we are creating txhandlers for
    let round_idx = match index {
        RoundIndex::Collateral => 0, // impossible, checked before
        RoundIndex::Round(idx) => idx,
    };
    // iterate starting from second round to the requested round
    for round_idx in RoundIndex::iter_rounds_range(1, round_idx + 1) {
        round_txhandler = create_round_txhandler(
            operator_xonly_pk,
            RoundTxInput::Prevout(Box::new(
                ready_to_reimburse_txhandler
                    .get_spendable_output(UtxoVout::CollateralInReadyToReimburse)?,
            )),
            pubkeys.get_keys_for_round(round_idx)?,
            paramset,
        )?;
        ready_to_reimburse_txhandler =
            create_ready_to_reimburse_txhandler(&round_txhandler, operator_xonly_pk, paramset)?;
    }
    Ok((round_txhandler, ready_to_reimburse_txhandler))
}

/// Creates a [`TxHandler`] for the `ready_to_reimburse_tx`.
///
/// # Inputs
/// 1. RoundTx: BurnConnector utxo
///
/// # Outputs
/// 1. Operator's collateral
/// 2. Anchor output for CPFP
///
/// # Arguments
/// * `round_txhandler` - The round transaction handler providing the input.
/// * `operator_xonly_pk` - The operator's x-only public key.
/// * `paramset` - Protocol parameter set.
///
/// # Returns
/// A [`TxHandler`] for the ready-to-reimburse transaction, or a [`BridgeError`] if construction fails.
pub fn create_ready_to_reimburse_txhandler(
    round_txhandler: &TxHandler,
    operator_xonly_pk: XOnlyPublicKey,
    paramset: &'static ProtocolParamset,
) -> Result<TxHandler, BridgeError> {
    let prevout = round_txhandler.get_spendable_output(UtxoVout::CollateralInRound)?;
    let prev_value = prevout.get_prevout().value;

    Ok(TxHandlerBuilder::new(TransactionType::ReadyToReimburse)
        .with_version(NON_STANDARD_V3)
        .add_input(
            NormalSignatureKind::OperatorSighashDefault,
            prevout,
            SpendPath::KeySpend,
            DEFAULT_SEQUENCE,
        )
        .add_output(UnspentTxOut::from_scripts(
            prev_value - paramset.anchor_amount(),
            vec![],
            Some(operator_xonly_pk),
            paramset.network,
        ))
        .add_output(UnspentTxOut::from_partial(
            builder::transaction::anchor_output(paramset.anchor_amount()),
        ))
        .finalize())
}

/// Creates a vector of [`TxHandler`] for `unspent_kickoff_tx` transactions.
/// These transactions can be sent if an operator sends ReadyToReimburse transaction without spending all the kickoff utxos of the round.
///
/// # Inputs
/// 1. ReadyToReimburseTx: BurnConnector utxo
/// 2. RoundTx: Any kickoff utxo of the same round
///
/// # Outputs
/// 1. Anchor output for CPFP
///
/// # Arguments
/// * `round_txhandler` - The round transaction handler providing the kickoff utxos.
/// * `ready_to_reimburse_txhandler` - The ready-to-reimburse transaction handler providing the collateral.
/// * `paramset` - Protocol parameter set.
///
/// # Returns
/// A vector of [`TxHandler`] for unspent kickoff transactions, or a [`BridgeError`] if construction fails.
pub fn create_unspent_kickoff_txhandlers(
    round_txhandler: &TxHandler,
    ready_to_reimburse_txhandler: &TxHandler,
    paramset: &'static ProtocolParamset,
) -> Result<Vec<TxHandler>, BridgeError> {
    let mut txhandlers = Vec::new();
    for idx in 0..paramset.num_kickoffs_per_round {
        txhandlers.push(
            TxHandlerBuilder::new(TransactionType::UnspentKickoff(idx))
                .with_version(NON_STANDARD_V3)
                .add_input(
                    (NumberedSignatureKind::UnspentKickoff1, idx as i32),
                    ready_to_reimburse_txhandler
                        .get_spendable_output(UtxoVout::CollateralInReadyToReimburse)?,
                    SpendPath::KeySpend,
                    DEFAULT_SEQUENCE,
                )
                .add_input(
                    (NumberedSignatureKind::UnspentKickoff2, idx as i32),
                    round_txhandler.get_spendable_output(UtxoVout::Kickoff(idx))?,
                    SpendPath::ScriptSpend(1),
                    Sequence::from_height(1),
                )
                .add_output(UnspentTxOut::from_partial(
                    builder::transaction::anchor_output(paramset.anchor_amount()),
                ))
                .finalize(),
        );
    }
    Ok(txhandlers)
}

/// Creates a [`TxHandler`] for burning unused kickoff connectors.
///
/// # Inputs
/// 1. RoundTx: Kickoff utxo(s) (per unused connector)
///
/// # Outputs
/// 1. Change output to the provided address
/// 2. Anchor output for CPFP
///
/// # Arguments
/// * `round_txhandler` - The round transaction handler providing the input.
/// * `unused_kickoff_connectors_indices` - Indices of the unused kickoff connectors (0-indexed).
/// * `change_address` - The address to send the change to.
///
/// # Returns
/// A [`TxHandler`] for burning unused kickoff connectors, or a [`BridgeError`] if construction fails.
pub fn create_burn_unused_kickoff_connectors_txhandler(
    round_txhandler: &TxHandler,
    unused_kickoff_connectors_indices: &[usize],
    change_address: &Address,
    paramset: &'static ProtocolParamset,
) -> Result<TxHandler, BridgeError> {
    let mut tx_handler_builder =
        TxHandlerBuilder::new(TransactionType::BurnUnusedKickoffConnectors)
            .with_version(NON_STANDARD_V3);
    for &idx in unused_kickoff_connectors_indices {
        tx_handler_builder = tx_handler_builder.add_input(
            NormalSignatureKind::OperatorSighashDefault,
            round_txhandler.get_spendable_output(UtxoVout::Kickoff(idx))?,
            SpendPath::ScriptSpend(1),
            Sequence::from_height(1),
        );
    }
    if !paramset.bridge_nonstandard {
        // if we use standard tx's, kickoff utxo's will hold some sats so we can return the change to the change address
        // but if we use nonstandard tx's with 0 sat values then the change is 0 anyway, no need to add an output
        tx_handler_builder = tx_handler_builder.add_output(UnspentTxOut::from_partial(TxOut {
            value: MIN_TAPROOT_AMOUNT,
            script_pubkey: change_address.script_pubkey(),
        }));
    }
    tx_handler_builder = tx_handler_builder.add_output(UnspentTxOut::from_partial(
        builder::transaction::anchor_output(paramset.anchor_amount()),
    ));
    Ok(tx_handler_builder.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::protocol::REGTEST_PARAMSET;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_create_round_nth_txhandler_and_round_txhandlers() {
        // check if round_nth_txhandler and round_txhandlers are consistent with each other
        let op_xonly_pk = XOnlyPublicKey::from_str(
            "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
        )
        .expect("this key is valid");
        let paramset = &REGTEST_PARAMSET;
        let input_outpoint = OutPoint::new(bitcoin::Txid::all_zeros(), 0);
        let input_amount = Amount::from_sat(10000000000);
        let pubkeys = KickoffWinternitzKeys::new(
            vec![vec![[0u8; 20]; 44]; paramset.num_round_txs * paramset.num_kickoffs_per_round],
            paramset.num_round_txs,
            paramset.num_kickoffs_per_round,
        );

        let mut round_tx_input = RoundTxInput::Collateral(input_outpoint, input_amount);

        for i in 0..paramset.num_round_txs {
            let (round_nth_txhandler, ready_to_reimburse_nth_txhandler) =
                create_round_nth_txhandler(
                    op_xonly_pk,
                    input_outpoint,
                    input_amount,
                    RoundIndex::Round(i),
                    &pubkeys,
                    paramset,
                )
                .unwrap();

            let round_txhandler = create_round_txhandler(
                op_xonly_pk,
                round_tx_input,
                pubkeys.get_keys_for_round(RoundIndex::Round(i)).unwrap(),
                paramset,
            )
            .unwrap();

            let ready_to_reimburse_txhandler =
                create_ready_to_reimburse_txhandler(&round_txhandler, op_xonly_pk, paramset)
                    .unwrap();

            assert_eq!(round_nth_txhandler.get_txid(), round_txhandler.get_txid());
            assert_eq!(
                ready_to_reimburse_nth_txhandler.get_txid(),
                ready_to_reimburse_txhandler.get_txid()
            );

            let prev_ready_to_reimburse_txhandler = ready_to_reimburse_txhandler;
            round_tx_input = RoundTxInput::Prevout(Box::new(
                prev_ready_to_reimburse_txhandler
                    .get_spendable_output(UtxoVout::CollateralInReadyToReimburse)
                    .unwrap(),
            ));
        }
    }
}
