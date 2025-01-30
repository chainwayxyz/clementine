use crate::builder;
use crate::builder::transaction::txhandler::TxHandler;
use crate::builder::transaction::*;
use crate::constants::OPERATOR_CHALLENGE_AMOUNT;
use bitcoin::opcodes::all::OP_CHECKSIG;
use bitcoin::{taproot::TaprootSpendInfo, Amount, OutPoint, ScriptBuf, TxOut, XOnlyPublicKey};
use bitvm::signatures::winternitz;

/// Creates a [`TxHandler`] for the `watchtower_challenge_kickoff_tx`. This transaction can be sent by anyone.
/// When spent, the outputs of this transaction will reveal the Groth16 proofs with their public inputs for the longest
/// chain proof, signed by the corresponding watchtowers using WOTS.
pub fn create_watchtower_challenge_kickoff_txhandler(
    kickoff_tx_handler: &TxHandler,
    num_watchtowers: u32,
    watchtower_xonly_pks: &[XOnlyPublicKey],
    watchtower_challenge_winternitz_pks: &[Vec<[u8; 20]>],
    network: bitcoin::Network,
) -> TxHandler {
    let tx_ins = create_tx_ins(
        vec![OutPoint {
            txid: kickoff_tx_handler.txid,
            vout: 0,
        }]
        .into(),
    );

    let verifier =
        winternitz::Winternitz::<winternitz::ListpickVerifier, winternitz::TabledConverter>::new();
    let wots_params = winternitz::Parameters::new(240, 4);

    let mut scripts: Vec<Vec<ScriptBuf>> = Vec::new();
    let mut spendinfos: Vec<Option<TaprootSpendInfo>> = Vec::new();

    let mut tx_outs = (0..num_watchtowers)
        .map(|i| {
            let mut x = verifier.checksig_verify(
                &wots_params,
                &watchtower_challenge_winternitz_pks[i as usize],
            );
            x = x.push_x_only_key(&watchtower_xonly_pks[i as usize]);
            x = x.push_opcode(OP_CHECKSIG); // TODO: Add checksig in the beginning
            let x = x.compile();
            let (watchtower_challenge_addr, watchtower_challenge_spend) =
                builder::address::create_taproot_address(&[x.clone()], None, network);
            scripts.push(vec![x]);
            spendinfos.push(Some(watchtower_challenge_spend));
            TxOut {
                value: Amount::from_sat(2000), // TOOD: Hand calculate this
                script_pubkey: watchtower_challenge_addr.script_pubkey(), // TODO: Add winternitz checks here
            }
        })
        .collect::<Vec<_>>();

    // add the anchor output
    tx_outs.push(builder::script::anchor_output());
    scripts.push(vec![]);
    spendinfos.push(None);

    let wcptx = create_btc_tx(tx_ins, tx_outs);

    TxHandler {
        txid: wcptx.compute_txid(),
        tx: wcptx,
        prevouts: vec![kickoff_tx_handler.tx.output[0].clone()],
        prev_scripts: vec![kickoff_tx_handler.out_scripts[0].clone()],
        prev_taproot_spend_infos: vec![kickoff_tx_handler.out_taproot_spend_infos[0].clone()],
        out_scripts: scripts,
        out_taproot_spend_infos: spendinfos,
    }
}

/// Creates a "simplified "[`TxHandler`] for the `watchtower_challenge_kickoff_tx`. The purpose of the simplification
/// is that when the verifiers are generating related sighashes, they only need to know the output addresses or the
/// input UTXOs. They do not need to know output scripts or spendinfos.
pub fn create_watchtower_challenge_kickoff_txhandler_simplified(
    kickoff_tx_handler: &TxHandler,
    num_watchtowers: u32,
    watchtower_challenge_addresses: &[ScriptBuf],
) -> TxHandler {
    let tx_ins = create_tx_ins(
        vec![OutPoint {
            txid: kickoff_tx_handler.txid,
            vout: 0,
        }]
        .into(),
    );
    let mut tx_outs = (0..num_watchtowers)
        .map(|i| {
            TxOut {
                value: Amount::from_sat(2000), // TODO: Hand calculate this
                script_pubkey: watchtower_challenge_addresses[i as usize].clone(),
            }
        })
        .collect::<Vec<_>>();

    // add the anchor output
    tx_outs.push(builder::script::anchor_output());

    let wcptx = create_btc_tx(tx_ins, tx_outs);

    TxHandler {
        txid: wcptx.compute_txid(),
        tx: wcptx,
        prevouts: vec![kickoff_tx_handler.tx.output[0].clone()],
        prev_scripts: vec![kickoff_tx_handler.out_scripts[0].clone()],
        prev_taproot_spend_infos: vec![kickoff_tx_handler.out_taproot_spend_infos[0].clone()],
        out_scripts: vec![],
        out_taproot_spend_infos: vec![],
    }
}

/// Creates a [`TxHandler`] for the `watchtower_challenge_tx`. This transaction
/// is sent by the watchtowers to reveal their Groth16 proofs with their public
/// inputs for the longest chain proof, signed by the corresponding watchtowers
/// using WOTS. The output of this transaction can be spend by:
/// 1- the operator with revealing the preimage for the corresponding watchtower
/// 2- the NofN after 0.5 week `using kickoff_tx.output[2]`, which will also prevent
/// the operator from sending `assert_begin_tx`.
/// The revealed preimage will later be used to send `disprove_tx` if the operator
/// claims that the corresponding watchtower did not challenge them.
pub fn create_watchtower_challenge_txhandler(
    wcp_txhandler: &TxHandler,
    watchtower_idx: usize,
    operator_unlock_hash: &[u8; 20],
    nofn_xonly_pk: XOnlyPublicKey,
    operator_xonly_pk: XOnlyPublicKey,
    network: bitcoin::Network,
) -> TxHandler {
    let tx_ins = create_tx_ins(
        vec![OutPoint {
            txid: wcp_txhandler.txid,
            vout: watchtower_idx as u32,
        }]
        .into(),
    );

    let nofn_halfweek =
        builder::script::generate_checksig_relative_timelock_script(nofn_xonly_pk, 7 * 24 * 6 / 2); // 0.5 week
    let operator_with_preimage =
        builder::script::actor_with_preimage_script(operator_xonly_pk, operator_unlock_hash);
    let (op_or_nofn_halfweek, op_or_nofn_halfweek_spend) = builder::address::create_taproot_address(
        &[operator_with_preimage.clone(), nofn_halfweek.clone()],
        None,
        network,
    );

    let tx_outs = vec![
        TxOut {
            value: Amount::from_sat(1000), // TODO: Hand calculate this
            script_pubkey: op_or_nofn_halfweek.script_pubkey(),
        },
        builder::script::anchor_output(),
    ];

    let wcptx2 = create_btc_tx(tx_ins, tx_outs);

    TxHandler {
        txid: wcptx2.compute_txid(),
        tx: wcptx2,
        prevouts: vec![wcp_txhandler.tx.output[watchtower_idx].clone()],
        prev_scripts: vec![wcp_txhandler.out_scripts[watchtower_idx].clone()],
        prev_taproot_spend_infos: vec![
            wcp_txhandler.out_taproot_spend_infos[watchtower_idx].clone()
        ],
        out_scripts: vec![vec![operator_with_preimage, nofn_halfweek], vec![]],
        out_taproot_spend_infos: vec![Some(op_or_nofn_halfweek_spend), None],
    }
}

// TODO: Reduce code duplication
pub fn create_watchtower_challenge_txhandler_simplified(
    wcp_txhandler: &TxHandler,
    watchtower_idx: usize,
    operator_unlock_hash: &[u8; 20],
    nofn_xonly_pk: XOnlyPublicKey,
    operator_xonly_pk: XOnlyPublicKey,
    network: bitcoin::Network,
) -> TxHandler {
    let tx_ins = create_tx_ins(
        vec![OutPoint {
            txid: wcp_txhandler.txid,
            vout: watchtower_idx as u32,
        }]
        .into(),
    );

    let nofn_halfweek =
        builder::script::generate_checksig_relative_timelock_script(nofn_xonly_pk, 7 * 24 * 6 / 2); // 0.5 week
    let operator_with_preimage =
        builder::script::actor_with_preimage_script(operator_xonly_pk, operator_unlock_hash);
    let (op_or_nofn_halfweek, op_or_nofn_halfweek_spend) = builder::address::create_taproot_address(
        &[operator_with_preimage.clone(), nofn_halfweek.clone()],
        None,
        network,
    );

    let tx_outs = vec![
        TxOut {
            value: Amount::from_sat(1000), // TODO: Hand calculate this
            script_pubkey: op_or_nofn_halfweek.script_pubkey(),
        },
        builder::script::anchor_output(),
    ];

    let wcptx2 = create_btc_tx(tx_ins, tx_outs);

    TxHandler {
        txid: wcptx2.compute_txid(),
        tx: wcptx2,
        prevouts: vec![],
        prev_scripts: vec![],
        prev_taproot_spend_infos: vec![],
        out_scripts: vec![vec![operator_with_preimage, nofn_halfweek], vec![]],
        out_taproot_spend_infos: vec![Some(op_or_nofn_halfweek_spend), None],
    }
}

/// Creates a [`TxHandler`] for the `operator_challenge_NACK_tx`. This transaction will force
/// the operator to reveal the preimage for the corresponding watchtower since if they do not
/// reveal the preimage, the NofN will be able to spend the output after 0.5 week, which will
/// prevent the operator from sending `assert_begin_tx`.
pub fn create_operator_challenge_nack_txhandler(
    watchtower_challenge_txhandler: &TxHandler,
    kickoff_txhandler: &TxHandler,
) -> TxHandler {
    let tx_ins = create_tx_ins(
        vec![
            (
                OutPoint {
                    txid: watchtower_challenge_txhandler.txid,
                    vout: 0,
                },
                Some(7 * 24 * 6 / 2),
            ),
            (
                OutPoint {
                    txid: kickoff_txhandler.txid,
                    vout: 2,
                },
                None,
            ),
        ]
        .into(),
    );

    let tx_outs = vec![builder::script::anchor_output()];
    let challenge_nack_tx = create_btc_tx(tx_ins, tx_outs);

    TxHandler {
        txid: challenge_nack_tx.compute_txid(),
        tx: challenge_nack_tx,
        prevouts: vec![
            watchtower_challenge_txhandler.tx.output[0].clone(),
            kickoff_txhandler.tx.output[2].clone(),
        ],
        prev_scripts: vec![
            watchtower_challenge_txhandler.out_scripts[0].clone(),
            kickoff_txhandler.out_scripts[2].clone(),
        ],
        prev_taproot_spend_infos: vec![
            watchtower_challenge_txhandler.out_taproot_spend_infos[0].clone(),
            kickoff_txhandler.out_taproot_spend_infos[2].clone(),
        ],
        out_scripts: vec![vec![]],
        out_taproot_spend_infos: vec![None],
    }
}

/// Creates a [`TxHandler`] for the `already_disproved_tx`. This transaction will be sent by NofN, meaning
/// that the operator was malicious. This transaction "burns" the operator's burn connector, kicking the
/// operator out of the system.
pub fn create_already_disproved_txhandler(
    assert_end_txhandler: &TxHandler,
    sequential_collateral_txhandler: &TxHandler,
) -> TxHandler {
    let tx_ins = create_tx_ins(
        vec![
            (
                OutPoint {
                    txid: assert_end_txhandler.txid,
                    vout: 1,
                },
                Some(7 * 24 * 6 * 2),
            ),
            (
                OutPoint {
                    txid: sequential_collateral_txhandler.txid,
                    vout: 0,
                },
                None,
            ),
        ]
        .into(),
    );

    let tx_outs = vec![builder::script::anchor_output()];

    let disprove_tx = create_btc_tx(tx_ins, tx_outs);

    TxHandler {
        txid: disprove_tx.compute_txid(),
        tx: disprove_tx,
        prevouts: vec![
            assert_end_txhandler.tx.output[1].clone(),
            sequential_collateral_txhandler.tx.output[0].clone(),
        ],
        prev_scripts: vec![
            assert_end_txhandler.out_scripts[1].clone(),
            sequential_collateral_txhandler.out_scripts[0].clone(),
        ],
        prev_taproot_spend_infos: vec![
            assert_end_txhandler.out_taproot_spend_infos[1].clone(),
            sequential_collateral_txhandler.out_taproot_spend_infos[0].clone(),
        ],
        out_scripts: vec![vec![]],
        out_taproot_spend_infos: vec![None],
    }
}

/// Creates a [`TxHandler`] for the `disprove_tx`. This transaction will be sent by NofN, meaning
/// that the operator was malicious. This transaction burns the operator's burn connector, kicking the
/// operator out of the system.
pub fn create_disprove_txhandler(
    assert_end_txhandler: &TxHandler,
    sequential_collateral_txhandler: &TxHandler,
) -> TxHandler {
    let tx_ins = create_tx_ins(
        vec![
            OutPoint {
                txid: assert_end_txhandler.txid,
                vout: 0,
            },
            OutPoint {
                txid: sequential_collateral_txhandler.txid,
                vout: 0,
            },
        ]
        .into(),
    );

    let tx_outs = vec![builder::script::anchor_output()];

    let disprove_tx = create_btc_tx(tx_ins, tx_outs);

    TxHandler {
        txid: disprove_tx.compute_txid(),
        tx: disprove_tx,
        prevouts: vec![
            assert_end_txhandler.tx.output[0].clone(),
            sequential_collateral_txhandler.tx.output[0].clone(),
        ],
        prev_scripts: vec![
            assert_end_txhandler.out_scripts[0].clone(),
            sequential_collateral_txhandler.out_scripts[0].clone(),
        ],
        prev_taproot_spend_infos: vec![
            assert_end_txhandler.out_taproot_spend_infos[0].clone(),
            sequential_collateral_txhandler.out_taproot_spend_infos[0].clone(),
        ],
        out_scripts: vec![vec![]],
        out_taproot_spend_infos: vec![None],
    }
}

/// Creates a [`TxHandler`] for the `challenge`. This transaction is for covering
/// the operators' cost for a challenge to prevent people from maliciously
/// challenging them and causing them to lose money.
pub fn create_challenge_txhandler(
    kickoff_txhandler: &TxHandler,
    operator_reimbursement_address: &bitcoin::Address,
) -> TxHandler {
    let tx_ins = create_tx_ins(
        vec![OutPoint {
            txid: kickoff_txhandler.txid,
            vout: 1,
        }]
        .into(),
    );

    let tx_outs = vec![TxOut {
        value: OPERATOR_CHALLENGE_AMOUNT,
        script_pubkey: operator_reimbursement_address.script_pubkey(),
    }];

    let challenge_tx = create_btc_tx(tx_ins, tx_outs);

    TxHandler {
        txid: challenge_tx.compute_txid(),
        tx: challenge_tx,
        prevouts: vec![kickoff_txhandler.tx.output[1].clone()],
        prev_scripts: vec![kickoff_txhandler.out_scripts[1].clone()],
        prev_taproot_spend_infos: vec![kickoff_txhandler.out_taproot_spend_infos[1].clone()],
        out_scripts: vec![vec![]],
        out_taproot_spend_infos: vec![None],
    }
}
