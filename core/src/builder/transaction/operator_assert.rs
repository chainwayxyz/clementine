use crate::builder;
use crate::builder::address::create_taproot_address;
use crate::constants::{MIN_TAPROOT_AMOUNT, PARALLEL_ASSERT_TX_CHAIN_SIZE};
use crate::utils::SECP;
use bitcoin::hashes::Hash;
use bitcoin::taproot::TaprootBuilder;
use bitcoin::{
    taproot::TaprootSpendInfo, Address, Amount, OutPoint, ScriptBuf, TxIn, TxOut, XOnlyPublicKey,
};
use bitcoin::{TapNodeHash, Transaction, Txid};

pub use crate::builder::transaction::txhandler::TxHandler;
pub use crate::builder::transaction::*;

/// Creates a [`TxHandler`] for the `operator_challenge_ACK_tx`. This transaction will allow the operator
/// to send the `assert_begin_tx` to basically respond to the challenge(s). This transaction will allow
/// the operator to create `PARALLEL_ASSERT_TX_CHAIN_SIZE` outputs so that they can send `mini_assert_tx`s
/// in parallel. These transactions allow the operator to "commit" their intermediate values inside the
/// Groth16 verifier script. Commitments are possible using Winternitz OTSs.
pub fn create_assert_begin_txhandler(
    kickoff_txhandler: &TxHandler,
    assert_tx_addrs: &[ScriptBuf],
    _network: bitcoin::Network,
) -> TxHandler {
    let tx_ins: Vec<TxIn> = create_tx_ins(
        vec![(
            OutPoint {
                txid: kickoff_txhandler.txid,
                vout: 2,
            },
            Some(7 * 24 * 6 / 2 * 5),
        )]
        .into(),
    );

    let mut scripts: Vec<Vec<ScriptBuf>> = Vec::new();
    let mut spendinfos: Vec<Option<TaprootSpendInfo>> = Vec::new();

    let mut txouts = vec![];

    txouts.extend(
        assert_tx_addrs
            .iter()
            .take(PARALLEL_ASSERT_TX_CHAIN_SIZE)
            .map(|addr| TxOut {
                value: MIN_TAPROOT_AMOUNT, // Minimum amount for a taproot output
                script_pubkey: addr.clone(),
            }),
    );

    txouts.push(builder::script::anchor_output());
    scripts.push(vec![]);
    spendinfos.push(None);

    let assert_begin_tx = create_btc_tx(tx_ins, txouts);

    TxHandler {
        txid: assert_begin_tx.compute_txid(),
        tx: assert_begin_tx,
        prevouts: vec![kickoff_txhandler.tx.output[2].clone()],
        prev_scripts: vec![kickoff_txhandler.out_scripts[2].clone()],
        prev_taproot_spend_infos: vec![kickoff_txhandler.out_taproot_spend_infos[2].clone()],
        out_scripts: scripts,
        out_taproot_spend_infos: spendinfos,
    }
}

/// Creates the `mini_assert_tx` for `assert_begin_tx -> assert_end_tx` flow.
pub fn create_mini_assert_tx(
    prev_txid: Txid,
    prev_vout: u32,
    out_script: ScriptBuf,
    _network: bitcoin::Network,
) -> Transaction {
    let tx_ins = create_tx_ins(
        vec![OutPoint {
            txid: prev_txid,
            vout: prev_vout,
        }]
        .into(),
    );

    let tx_outs = vec![
        TxOut {
            value: Amount::from_sat(330),
            script_pubkey: out_script,
        },
        builder::script::anchor_output(),
    ];

    create_btc_tx(tx_ins, tx_outs)
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
) -> TxHandler {
    let mut last_mini_assert_txid =
        vec![assert_begin_txhandler.txid; PARALLEL_ASSERT_TX_CHAIN_SIZE];

    for i in PARALLEL_ASSERT_TX_CHAIN_SIZE..assert_tx_addrs.len() {
        let mini_assert_tx = create_mini_assert_tx(
            last_mini_assert_txid[i % PARALLEL_ASSERT_TX_CHAIN_SIZE],
            // if i - PARALLEL_ASSERT_TX_CHAIN_SIZE < PARALLEL_ASSERT_TX_CHAIN_SIZE, then i - PARALLEL_ASSERT_TX_CHAIN_SIZE, otherwise 0
            if i - PARALLEL_ASSERT_TX_CHAIN_SIZE < PARALLEL_ASSERT_TX_CHAIN_SIZE {
                i as u32 - PARALLEL_ASSERT_TX_CHAIN_SIZE as u32
            } else {
                0
            },
            assert_tx_addrs[i].clone(),
            network,
        );
        last_mini_assert_txid[i % PARALLEL_ASSERT_TX_CHAIN_SIZE] = mini_assert_tx.compute_txid();
    }

    let mut txins = vec![];

    txins.extend(
        last_mini_assert_txid
            .into_iter()
            .take(PARALLEL_ASSERT_TX_CHAIN_SIZE)
            .map(|txid| OutPoint { txid, vout: 0 }),
    );

    txins.push(OutPoint {
        txid: kickoff_txhandler.txid,
        vout: 3,
    });

    let disprove_taproot_spend_info = TaprootBuilder::new()
        .add_hidden_node(0, TapNodeHash::from_slice(root_hash).unwrap())
        .unwrap()
        .finalize(&SECP, nofn_xonly_pk) // TODO: we should convert this to script spend but we only have partial access to the taptree
        .unwrap();

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
    let disprove_addr_pubkey = disprove_address.script_pubkey();
    let tx_outs = vec![
        TxOut {
            value: MIN_TAPROOT_AMOUNT,
            script_pubkey: disprove_addr_pubkey.clone(),
        },
        TxOut {
            value: MIN_TAPROOT_AMOUNT,
            script_pubkey: connector_addr.script_pubkey(),
        },
        builder::script::anchor_output(),
    ];

    let assert_end_tx = create_btc_tx(create_tx_ins(txins.into()), tx_outs);

    // We do not create the scripts for Parallel assert txs, so that deposit process for verifiers is faster
    // Because of this we do not have scripts, spendinfos etc. for parallel asserts
    // For operator to create txs for parallel asserts and assert_end_txs, they need to create the scripts themselves
    // That's why prevout variables have dummy values here
    let mut prevouts = (0..PARALLEL_ASSERT_TX_CHAIN_SIZE)
        .map(|_| TxOut {
            value: MIN_TAPROOT_AMOUNT,
            script_pubkey: disprove_addr_pubkey.clone(), // Dummy random script pubkey, not the actual pubkey
        })
        .collect::<Vec<_>>();
    prevouts.push(kickoff_txhandler.tx.output[3].clone());

    let mut scripts = (0..PARALLEL_ASSERT_TX_CHAIN_SIZE)
        .map(|_| vec![]) // TODO: Dummy empty scripts, not the actual script
        .collect::<Vec<_>>();
    scripts.push(kickoff_txhandler.out_scripts[3].clone());

    let mut prev_taproot_spend_infos = (0..PARALLEL_ASSERT_TX_CHAIN_SIZE)
        .map(|_| None) // TODO: Dummy empty spendinfo, not the actual spendinfo
        .collect::<Vec<_>>();
    prev_taproot_spend_infos.push(kickoff_txhandler.out_taproot_spend_infos[3].clone());

    TxHandler {
        txid: assert_end_tx.compute_txid(),
        tx: assert_end_tx,
        prevouts,
        prev_scripts: scripts,
        prev_taproot_spend_infos,
        out_scripts: vec![vec![], vec![nofn_1week, nofn_2week], vec![]],
        out_taproot_spend_infos: vec![
            Some(disprove_taproot_spend_info),
            Some(connector_spend),
            None,
        ],
    }
}

/// Creates a [`TxHandler`] for the `disprove_timeout_tx`. This transaction will be sent by the operator
/// to be able to send `reimburse_tx` later.
pub fn create_disprove_timeout_txhandler(
    assert_end_txhandler: &TxHandler,
    operator_xonly_pk: XOnlyPublicKey,
    network: bitcoin::Network,
) -> TxHandler {
    let tx_ins = create_tx_ins(
        vec![
            (
                OutPoint {
                    txid: assert_end_txhandler.txid,
                    vout: 0,
                },
                None,
            ),
            (
                OutPoint {
                    txid: assert_end_txhandler.txid,
                    vout: 1,
                },
                Some(7 * 24 * 6),
            ),
        ]
        .into(),
    );

    let (op_address, op_spend) = create_taproot_address(&[], Some(operator_xonly_pk), network);

    let tx_outs = vec![TxOut {
        value: MIN_TAPROOT_AMOUNT,
        script_pubkey: op_address.script_pubkey(),
    }];

    let disprove_tx = create_btc_tx(tx_ins, tx_outs);

    TxHandler {
        txid: disprove_tx.compute_txid(),
        tx: disprove_tx,
        prevouts: vec![
            assert_end_txhandler.tx.output[0].clone(),
            assert_end_txhandler.tx.output[1].clone(),
        ],
        prev_scripts: vec![
            assert_end_txhandler.out_scripts[0].clone(),
            assert_end_txhandler.out_scripts[1].clone(),
        ],
        prev_taproot_spend_infos: vec![
            assert_end_txhandler.out_taproot_spend_infos[0].clone(),
            assert_end_txhandler.out_taproot_spend_infos[1].clone(),
        ],
        out_scripts: vec![vec![]],
        out_taproot_spend_infos: vec![Some(op_spend)],
    }
}
