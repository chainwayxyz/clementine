use std::ops::{Div, Rem};

use crate::builder;
use crate::builder::address::create_taproot_address;
use crate::constants::{MIN_TAPROOT_AMOUNT, PARALLEL_ASSERT_TX_CHAIN_SIZE};
use crate::errors::BridgeError;
use crate::utils::SECP;
use bitcoin::hashes::Hash;
use bitcoin::taproot::TaprootBuilder;
use bitcoin::{Address, Amount, OutPoint, ScriptBuf, TxOut, XOnlyPublicKey};
use bitcoin::{Sequence, TapNodeHash, Txid};

pub use crate::builder::transaction::txhandler::TxHandler;
pub use crate::builder::transaction::*;

use self::input::SpendableTxIn;
use self::output::UnspentTxOut;

/// Creates a [`TxHandler`] for the `operator_challenge_ACK_tx`. This transaction will allow the operator
/// to send the `assert_begin_tx` to basically respond to the challenge(s). This transaction will allow
/// the operator to create `PARALLEL_ASSERT_TX_CHAIN_SIZE` outputs so that they can send `mini_assert_tx`s
/// in parallel. These transactions allow the operator to "commit" their intermediate values inside the
/// Groth16 verifier script. Commitments are possible using Winternitz OTSs.
pub fn create_assert_begin_txhandler(
    kickoff_txhandler: &TxHandler,
    assert_tx_addrs: &[ScriptBuf],
    _network: bitcoin::Network,
) -> Result<TxHandler<Unsigned>, BridgeError> {
    let mut builder = TxHandlerBuilder::new();

    // Add input from kickoff tx
    builder = builder.add_input(
        kickoff_txhandler
            .get_spendable_output(2)
            .ok_or(BridgeError::TxInputNotFound)?,
        Sequence::from_height(7 * 24 * 6 / 2 * 5),
    );

    // Add parallel assert outputs
    for addr in assert_tx_addrs.iter().take(PARALLEL_ASSERT_TX_CHAIN_SIZE) {
        builder = builder.add_output(UnspentTxOut::from_partial(TxOut {
            value: MIN_TAPROOT_AMOUNT,
            script_pubkey: addr.clone(),
        }));
    }

    // Add anchor output
    builder = builder.add_output(UnspentTxOut::from_partial(builder::script::anchor_output()));

    Ok(builder.finalize())
}

/// Creates the `mini_assert_tx` for `assert_begin_tx -> assert_end_tx` flow.
pub fn create_mini_assert_tx(
    prev_txid: Txid,
    prev_vout: u32,
    out_script: ScriptBuf,
    _network: bitcoin::Network,
) -> TxHandler<Unsigned> {
    let mut builder = TxHandlerBuilder::new();

    // Add input
    builder = builder.add_input(
        SpendableTxIn::from_partial(
            OutPoint {
                txid: prev_txid,
                vout: prev_vout,
            },
            TxOut {
                value: MIN_TAPROOT_AMOUNT,
                script_pubkey: out_script.clone(),
            },
        ),
        Sequence::ENABLE_RBF_NO_LOCKTIME,
    );

    // Add main output
    builder = builder.add_output(UnspentTxOut::from_partial(TxOut {
        value: Amount::from_sat(330),
        script_pubkey: out_script,
    }));

    // Add anchor output
    builder = builder.add_output(UnspentTxOut::from_partial(builder::script::anchor_output()));

    builder.finalize()
}

/// Creates a [`TxHandler`] for the `assert_end_tx`. When this transaction is sent,
/// There are three scenarios:
///
/// 1. If the operator is malicious and deliberately spends assert_end_tx.output[0]
///    inside a transaction other than `disprove_tx`, then they cannot send the
///    `disprove_timeout_tx` anymore. This means after 2 weeks, NofN can spend the
///    `already_disproved_tx`. If the operator does not allow this by spending
///    sequential_collateral_tx.output[0], then they cannot send the `reimburse_tx`.
/// 2. If the operator is malicious and does not spend assert_end_tx.output[0], then
///    their burn connector can be burned by using the `disprove_tx`.
/// 3. If the operator is honest and there is a challenge, then eventually they will
///    send the `disprove_timeout_tx` to be able to send the `reimburse_tx` later.
pub fn create_assert_end_txhandler(
    kickoff_txhandler: &TxHandler,
    assert_begin_txhandler: &TxHandler,
    assert_tx_addrs: &[ScriptBuf],
    root_hash: &[u8; 32],
    nofn_xonly_pk: XOnlyPublicKey,
    _public_input_wots: &[[u8; 20]],
    network: bitcoin::Network,
) -> Result<TxHandler, BridgeError> {
    let mut mini_tx_handlers = Vec::with_capacity(PARALLEL_ASSERT_TX_CHAIN_SIZE);

    let mini_assert_layer_count = assert_tx_addrs.len().div(PARALLEL_ASSERT_TX_CHAIN_SIZE);
    if assert_tx_addrs.len().rem(PARALLEL_ASSERT_TX_CHAIN_SIZE) != 0 {
        return Err(BridgeError::InvalidAssertTxAddrs);
    }

    // Create first layer of mini assert txs
    for i in 0..PARALLEL_ASSERT_TX_CHAIN_SIZE {
        let mini_assert_tx = create_mini_assert_tx(
            *assert_begin_txhandler.get_txid(),
            i as u32,
            assert_tx_addrs[i].clone(),
            network,
        );
        mini_tx_handlers.push(mini_assert_tx);
    }

    for layer in 1..mini_assert_layer_count {
        for i in 0..PARALLEL_ASSERT_TX_CHAIN_SIZE {
            let mini_assert_tx = create_mini_assert_tx(
                *mini_tx_handlers[i].get_txid(),
                0,
                assert_tx_addrs[i + layer * PARALLEL_ASSERT_TX_CHAIN_SIZE].clone(),
                network,
            );

            mini_tx_handlers[i] = mini_assert_tx;
        }
    }

    let mut builder = TxHandlerBuilder::new();

    for txhandler in mini_tx_handlers.into_iter() {
        builder = builder.add_input(
            txhandler
                .get_spendable_output(0)
                .ok_or(BridgeError::TxInputNotFound)?,
            Sequence::ENABLE_RBF_NO_LOCKTIME,
        );
    }

    builder = builder.add_input(
        kickoff_txhandler
            .get_spendable_output(3)
            .ok_or(BridgeError::TxInputNotFound)?,
        Sequence::ENABLE_RBF_NO_LOCKTIME,
    );

    let disprove_taproot_spend_info = TaprootBuilder::new()
        .add_hidden_node(0, TapNodeHash::from_slice(root_hash)?)
        .expect("statically correct taptree")
        .finalize(&SECP, nofn_xonly_pk) // TODO: we should convert this to script spend but we only have partial access to the taptree
        .expect("statically correct taptree");

    let disprove_address = Address::p2tr(
        &SECP,
        nofn_xonly_pk,
        disprove_taproot_spend_info.merkle_root(),
        network,
    );

    let nofn_1week =
        builder::script::generate_checksig_relative_timelock_script(nofn_xonly_pk, 7 * 24 * 6);
    let nofn_2week =
        builder::script::generate_checksig_relative_timelock_script(nofn_xonly_pk, 2 * 7 * 24 * 6);
    let (connector_addr, connector_spend) = builder::address::create_taproot_address(
        &[nofn_1week.clone(), nofn_2week.clone()],
        None,
        network,
    );

    // Add outputs
    builder = builder
        .add_output(UnspentTxOut::new(
            TxOut {
                value: MIN_TAPROOT_AMOUNT,
                script_pubkey: disprove_address.script_pubkey().clone(),
            },
            vec![],
            Some(disprove_taproot_spend_info),
        ))
        .add_output(UnspentTxOut::new(
            TxOut {
                value: MIN_TAPROOT_AMOUNT,
                script_pubkey: connector_addr.script_pubkey(),
            },
            vec![nofn_1week, nofn_2week],
            Some(connector_spend),
        ))
        .add_output(UnspentTxOut::new(
            builder::script::anchor_output(),
            vec![],
            None,
        ));

    // We do not create the scripts for Parallel assert txs, so that deposit process for verifiers is faster
    // Because of this we do not have scripts, spendinfos etc. for parallel asserts
    // For operator to create txs for parallel asserts and assert_end_txs, they need to create the scripts themselves
    // That's why prevout variables have dummy values here
    Ok(builder.finalize())
}
/// Creates a [`TxHandler`] for the `disprove_timeout_tx`. This transaction will be sent by the operator
/// to be able to send `reimburse_tx` later.
pub fn create_disprove_timeout_txhandler(
    assert_end_txhandler: &TxHandler,
    operator_xonly_pk: XOnlyPublicKey,
    network: bitcoin::Network,
) -> Result<TxHandler<Unsigned>, BridgeError> {
    let mut builder = TxHandlerBuilder::new();

    // Add inputs
    builder = builder
        .add_input(
            assert_end_txhandler
                .get_spendable_output(0)
                .ok_or(BridgeError::TxInputNotFound)?,
            Sequence::ENABLE_RBF_NO_LOCKTIME,
        )
        .add_input(
            assert_end_txhandler
                .get_spendable_output(1)
                .ok_or(BridgeError::TxInputNotFound)?,
            Sequence::from_height(7 * 24 * 6),
        );

    // Create operator address
    let (op_address, op_spend) = create_taproot_address(&[], Some(operator_xonly_pk), network);

    // Add output
    builder = builder.add_output(UnspentTxOut::new(
        TxOut {
            value: MIN_TAPROOT_AMOUNT,
            script_pubkey: op_address.script_pubkey(),
        },
        vec![],
        Some(op_spend),
    ));

    Ok(builder.finalize())
}
