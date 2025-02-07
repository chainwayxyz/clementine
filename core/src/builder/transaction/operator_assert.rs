use crate::builder;
use crate::builder::script::TimelockScript;
pub use crate::builder::transaction::txhandler::TxHandler;
pub use crate::builder::transaction::*;
use crate::constants::{BLOCKS_PER_WEEK, MIN_TAPROOT_AMOUNT, PARALLEL_ASSERT_TX_CHAIN_SIZE};
use crate::errors::BridgeError;
use crate::rpc::clementine::NormalSignatureKind;
use crate::utils::SECP;
use bitcoin::hashes::Hash;
use bitcoin::taproot::TaprootBuilder;
use bitcoin::{Address, Amount, OutPoint, ScriptBuf, TxOut, XOnlyPublicKey};
use bitcoin::{Sequence, TapNodeHash, Txid};
use std::sync::Arc;

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
        NormalSignatureKind::NotStored,
        kickoff_txhandler.get_spendable_output(2)?,
        builder::script::SpendPath::ScriptSpend(1),
        Sequence::from_height(BLOCKS_PER_WEEK / 2 * 5), // 2.5 weeks
    );

    // Add parallel assert outputs
    for addr in assert_tx_addrs.iter().take(PARALLEL_ASSERT_TX_CHAIN_SIZE) {
        builder = builder.add_output(UnspentTxOut::from_partial(TxOut {
            value: MIN_TAPROOT_AMOUNT,
            script_pubkey: addr.clone(),
        }));
    }

    Ok(builder
        .add_output(UnspentTxOut::from_partial(
            builder::transaction::anchor_output(),
        ))
        .finalize())
}

/// Creates the `mini_assert_tx` for `assert_begin_tx -> assert_end_tx` flow.
pub fn create_mini_assert_tx(
    prev_txid: Txid,
    prev_vout: u32,
    out_script: ScriptBuf,
    _network: bitcoin::Network,
) -> TxHandler<Unsigned> {
    let builder = TxHandlerBuilder::new();

    builder
        .add_input(
            NormalSignatureKind::NotStored,
            SpendableTxIn::new_partial(
                OutPoint {
                    txid: prev_txid,
                    vout: prev_vout,
                },
                TxOut {
                    value: MIN_TAPROOT_AMOUNT,
                    script_pubkey: out_script.clone(),
                },
            ),
            builder::script::SpendPath::ScriptSpend(0),
            DEFAULT_SEQUENCE,
        )
        .add_output(UnspentTxOut::from_partial(TxOut {
            value: Amount::from_sat(330),
            script_pubkey: out_script,
        }))
        .add_output(UnspentTxOut::from_partial(
            builder::transaction::anchor_output(),
        ))
        .finalize()
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
    network: bitcoin::Network,
) -> Result<TxHandler, BridgeError> {
    let mut mini_tx_handlers = Vec::with_capacity(PARALLEL_ASSERT_TX_CHAIN_SIZE);

    let mini_assert_layer_count = assert_tx_addrs
        .len()
        .div_ceil(PARALLEL_ASSERT_TX_CHAIN_SIZE);
    if assert_tx_addrs.len() < PARALLEL_ASSERT_TX_CHAIN_SIZE {
        return Err(BridgeError::InvalidAssertTxAddrs);
    }

    // We do not create the scripts for Parallel assert txs, so that deposit process for verifiers is faster
    // Because of this we do not have scripts, spendinfos etc. for parallel asserts
    // For operator to create txs for parallel asserts and assert_end_txs, they need to create the scripts themselves

    // Create first layer of mini assert txs
    for (i, addr) in assert_tx_addrs
        .iter()
        .take(PARALLEL_ASSERT_TX_CHAIN_SIZE)
        .enumerate()
    {
        let mini_assert_tx = create_mini_assert_tx(
            *assert_begin_txhandler.get_txid(),
            i as u32,
            addr.clone(),
            network,
        );
        mini_tx_handlers.push(mini_assert_tx);
    }

    for layer in 1..mini_assert_layer_count {
        for i in 0..PARALLEL_ASSERT_TX_CHAIN_SIZE {
            let assert_tx_idx = i + layer * PARALLEL_ASSERT_TX_CHAIN_SIZE;
            if assert_tx_idx >= assert_tx_addrs.len() {
                break;
            }

            let mini_assert_tx = create_mini_assert_tx(
                *mini_tx_handlers
                    .get(i)
                    .expect("previous assertions ensure the size")
                    .get_txid(),
                0,
                assert_tx_addrs
                    .get(assert_tx_idx)
                    .expect("checked before")
                    .clone(),
                network,
            );

            mini_tx_handlers[i] = mini_assert_tx;
        }
    }

    let mut builder = TxHandlerBuilder::new();

    for txhandler in mini_tx_handlers.into_iter() {
        builder = builder.add_input(
            NormalSignatureKind::NotStored,
            txhandler.get_spendable_output(0)?,
            builder::script::SpendPath::ScriptSpend(0),
            DEFAULT_SEQUENCE,
        );
    }

    builder = builder.add_input(
        NormalSignatureKind::AssertEndLast,
        kickoff_txhandler.get_spendable_output(3)?,
        builder::script::SpendPath::ScriptSpend(0),
        DEFAULT_SEQUENCE,
    );

    let disprove_taproot_spend_info = TaprootBuilder::new()
        .add_hidden_node(0, TapNodeHash::from_byte_array(*root_hash))
        .expect("empty taptree will accept a node at depth 0")
        .finalize(&SECP, nofn_xonly_pk) // TODO: we should convert this to script spend but we only have partial access to the taptree
        .expect("finalize always succeeds for taptree with single node at depth 0");

    let disprove_address = Address::p2tr(
        &SECP,
        nofn_xonly_pk,
        disprove_taproot_spend_info.merkle_root(),
        network,
    );

    let nofn_1week = Arc::new(TimelockScript::new(Some(nofn_xonly_pk), BLOCKS_PER_WEEK));
    let nofn_2week = Arc::new(TimelockScript::new(
        Some(nofn_xonly_pk),
        BLOCKS_PER_WEEK * 2,
    ));

    // Add outputs
    Ok(builder
        .add_output(UnspentTxOut::from_partial(TxOut {
            value: MIN_TAPROOT_AMOUNT,
            script_pubkey: disprove_address.script_pubkey().clone(),
        }))
        .add_output(UnspentTxOut::from_scripts(
            MIN_TAPROOT_AMOUNT,
            vec![nofn_1week, nofn_2week],
            None,
            network,
        ))
        .add_output(UnspentTxOut::new(
            builder::transaction::anchor_output(),
            vec![],
            None,
        ))
        .finalize())
}
/// Creates a [`TxHandler`] for the `disprove_timeout_tx`. This transaction will be sent by the operator
/// to be able to send `reimburse_tx` later.
pub fn create_disprove_timeout_txhandler(
    assert_end_txhandler: &TxHandler,
    operator_xonly_pk: XOnlyPublicKey,
    network: bitcoin::Network,
) -> Result<TxHandler<Unsigned>, BridgeError> {
    Ok(TxHandlerBuilder::new()
        .add_input(
            NormalSignatureKind::DisproveTimeout1,
            assert_end_txhandler.get_spendable_output(0)?,
            builder::script::SpendPath::ScriptSpend(0),
            DEFAULT_SEQUENCE,
        )
        .add_input(
            NormalSignatureKind::DisproveTimeout2,
            assert_end_txhandler.get_spendable_output(1)?,
            builder::script::SpendPath::ScriptSpend(0),
            Sequence::from_height(BLOCKS_PER_WEEK),
        )
        .add_output(UnspentTxOut::from_scripts(
            MIN_TAPROOT_AMOUNT,
            vec![],
            Some(operator_xonly_pk),
            network,
        ))
        .finalize())
}
