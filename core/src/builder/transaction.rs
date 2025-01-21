//! # Transaction Builder
//!
//! Transaction builder provides useful functions for building typical Bitcoin
//! transactions.

use super::address::create_taproot_address;
use crate::builder;
use crate::constants::{NUM_INTERMEDIATE_STEPS, PARALLEL_ASSERT_TX_CHAIN_SIZE};
use crate::utils::SECP;
use crate::{utils, EVMAddress, UTXO};
use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::Hash;
use bitcoin::opcodes::all::OP_CHECKSIG;
use bitcoin::script::PushBytesBuf;
use bitcoin::taproot::TaprootBuilder;
use bitcoin::{
    absolute, taproot::TaprootSpendInfo, Address, Amount, OutPoint, ScriptBuf, TxIn, TxOut,
    Witness, XOnlyPublicKey,
};
use bitcoin::{Network, TapNodeHash, Transaction, Txid};
use bitvm::signatures::winternitz;

/// Verbose information about a transaction.
#[derive(Debug, Clone)]
pub struct TxHandler {
    /// Transaction itself.
    pub tx: bitcoin::Transaction,
    /// Txid of the transaction, saved here to not repeatedly calculate it.
    pub txid: Txid,
    /// Previous outputs in [`TxOut`] format.
    pub prevouts: Vec<TxOut>,
    /// Taproot scripts for each previous output.
    pub prev_scripts: Vec<Vec<ScriptBuf>>,
    /// Taproot spend information for each previous output.
    pub prev_taproot_spend_infos: Vec<Option<TaprootSpendInfo>>,
    /// Taproot scripts for each tx output.
    pub out_scripts: Vec<Vec<ScriptBuf>>,
    /// Taproot spend information for each tx output.
    pub out_taproot_spend_infos: Vec<Option<TaprootSpendInfo>>,
}

// TODO: Move these constants to the config file
pub const KICKOFF_UTXO_AMOUNT_SATS: Amount = Amount::from_sat(100_000);

pub const KICKOFF_INPUT_AMOUNT: Amount = Amount::from_sat(100_000);
pub const MIN_TAPROOT_AMOUNT: Amount = Amount::from_sat(330);
pub const ANCHOR_AMOUNT: Amount = Amount::from_sat(240); // TODO: This will change to 0 in the future after Bitcoin v0.29.0
pub const OPERATOR_CHALLENGE_AMOUNT: Amount = Amount::from_sat(200_000_000);

/// Creates a [`TxHandler`] for `time_tx`. It will always use `input_txid`'s first vout as the input.
///
/// # Returns
///
/// A `time_tx` that has outputs of:
///
/// 1. Operator's Burn Connector
/// 2. Operator's Time Connector: timelocked utxo for operator for the entire withdrawal time
/// 3. Kickoff input utxo: this utxo will be the input for the kickoff tx
/// 4. P2Anchor: Anchor output for CPFP
pub fn create_sequential_collateral_txhandler(
    operator_xonly_pk: XOnlyPublicKey,
    input_txid: Txid,
    input_amount: Amount,
    timeout_block_count: i64,
    max_withdrawal_time_block_count: i64,
    num_kickoffs_per_timetx: usize,
    network: bitcoin::Network,
) -> TxHandler {
    let tx_ins = create_tx_ins(vec![OutPoint {
        txid: input_txid,
        vout: 0,
    }]);

    let max_withdrawal_time_locked_script = builder::script::generate_relative_timelock_script(
        operator_xonly_pk,
        max_withdrawal_time_block_count,
    );

    let timeout_block_count_locked_script =
        builder::script::generate_relative_timelock_script_no_key(timeout_block_count);

    let (op_address, op_spend) = create_taproot_address(&[], Some(operator_xonly_pk), network);
    let (reimburse_gen_connector, reimburse_gen_spend) =
        create_taproot_address(&[max_withdrawal_time_locked_script.clone()], None, network);
    let (kickoff_utxo, kickoff_utxo_spend) = create_taproot_address(
        &[timeout_block_count_locked_script.clone()],
        Some(operator_xonly_pk),
        network,
    );

    let kickoff_txout = TxOut {
        value: MIN_TAPROOT_AMOUNT,
        script_pubkey: kickoff_utxo.script_pubkey(),
    };

    let mut out_scripts = vec![vec![], vec![max_withdrawal_time_locked_script]];

    let mut out_taproot_spend_infos = vec![Some(op_spend.clone()), Some(reimburse_gen_spend)];

    let mut tx_outs = vec![
        TxOut {
            value: input_amount,
            script_pubkey: op_address.script_pubkey(),
        },
        TxOut {
            value: MIN_TAPROOT_AMOUNT,
            script_pubkey: reimburse_gen_connector.script_pubkey(),
        },
    ];
    // add kickoff utxos
    for _ in 0..num_kickoffs_per_timetx {
        tx_outs.push(kickoff_txout.clone());
        out_scripts.push(vec![timeout_block_count_locked_script.clone()]);
        out_taproot_spend_infos.push(Some(kickoff_utxo_spend.clone()));
    }
    // add anchor
    tx_outs.push(builder::script::anchor_output());
    out_scripts.push(vec![]);
    out_taproot_spend_infos.push(None);

    let time_tx1 = create_btc_tx(tx_ins, tx_outs);

    TxHandler {
        txid: time_tx1.compute_txid(),
        tx: time_tx1,
        prevouts: vec![TxOut {
            script_pubkey: op_address.script_pubkey(),
            value: input_amount,
        }],
        prev_taproot_spend_infos: vec![Some(op_spend.clone())],
        prev_scripts: vec![vec![]],
        out_scripts,
        out_taproot_spend_infos,
    }
}

pub fn create_reimburse_generator_txhandler(
    sequential_collateral_txhandler: &TxHandler,
    operator_xonly_pk: XOnlyPublicKey,
    num_kickoffs_per_timetx: usize,
    network: bitcoin::Network,
) -> TxHandler {
    let tx_ins = create_tx_ins(vec![
        OutPoint {
            txid: sequential_collateral_txhandler.txid,
            vout: 0,
        },
        OutPoint {
            txid: sequential_collateral_txhandler.txid,
            vout: 1,
        },
    ]);

    let (op_address, op_spend) = create_taproot_address(&[], Some(operator_xonly_pk), network);

    let reimburse_txout = TxOut {
        value: MIN_TAPROOT_AMOUNT,
        script_pubkey: op_address.script_pubkey(),
    };

    let mut out_scripts = vec![vec![]];

    let mut out_taproot_spend_infos = vec![Some(op_spend.clone())];

    let mut tx_outs = vec![TxOut {
        value: sequential_collateral_txhandler.tx.output[0].value,
        script_pubkey: op_address.script_pubkey(),
    }];

    // add reimburse utxos
    for _ in 0..num_kickoffs_per_timetx {
        tx_outs.push(reimburse_txout.clone());
        out_scripts.push(vec![]);
        out_taproot_spend_infos.push(Some(op_spend.clone()));
    }
    // add anchor
    tx_outs.push(builder::script::anchor_output());
    out_scripts.push(vec![]);
    out_taproot_spend_infos.push(None);

    let time_tx2 = create_btc_tx(tx_ins, tx_outs);

    TxHandler {
        txid: time_tx2.compute_txid(),
        tx: time_tx2,
        prevouts: vec![
            sequential_collateral_txhandler.tx.output[0].clone(),
            sequential_collateral_txhandler.tx.output[1].clone(),
        ],
        prev_scripts: vec![
            sequential_collateral_txhandler.out_scripts[0].clone(),
            sequential_collateral_txhandler.out_scripts[1].clone(),
        ],
        prev_taproot_spend_infos: vec![
            sequential_collateral_txhandler.out_taproot_spend_infos[0].clone(),
            sequential_collateral_txhandler.out_taproot_spend_infos[1].clone(),
        ],
        out_scripts,
        out_taproot_spend_infos,
    }
}

pub fn create_kickoff_utxo_timeout_txhandler(
    sequential_collateral_txhandler: &TxHandler,
    kickoff_idx: usize,
) -> TxHandler {
    let tx_ins = create_tx_ins(vec![OutPoint {
        txid: sequential_collateral_txhandler.txid,
        vout: 2 + kickoff_idx as u32,
    }]);

    // let tx_outs = vec![builder::script::anyone_can_spend_txout()];
    let tx_outs = vec![builder::script::anchor_output()];

    let tx = create_btc_tx(tx_ins, tx_outs);

    TxHandler {
        txid: tx.compute_txid(),
        tx,
        prevouts: vec![sequential_collateral_txhandler.tx.output[2 + kickoff_idx].clone()],
        prev_scripts: vec![sequential_collateral_txhandler.out_scripts[2 + kickoff_idx].clone()],
        prev_taproot_spend_infos: vec![sequential_collateral_txhandler.out_taproot_spend_infos
            [2 + kickoff_idx]
            .clone()],
        out_scripts: vec![vec![]],
        out_taproot_spend_infos: vec![None],
    }
}

/// Creates the move_tx.
pub fn create_move_tx(
    deposit_outpoint: OutPoint,
    nofn_xonly_pk: XOnlyPublicKey,
    bridge_amount_sats: Amount,
    network: bitcoin::Network,
) -> Transaction {
    let (musig2_address, _) = builder::address::create_musig2_address(nofn_xonly_pk, network);

    let tx_ins = create_tx_ins(vec![deposit_outpoint]);

    // let anyone_can_spend_txout = builder::script::anyone_can_spend_txout();
    // let move_txout = TxOut {
    //     value: bridge_amount_sats - anyone_can_spend_txout.value,
    //     script_pubkey: musig2_address.script_pubkey(),
    // };
    let anchor_output = builder::script::anchor_output();
    let move_txout = TxOut {
        value: bridge_amount_sats,
        script_pubkey: musig2_address.script_pubkey(),
    };

    // create_btc_tx(tx_ins, vec![move_txout, anyone_can_spend_txout])
    create_btc_tx(tx_ins, vec![move_txout, anchor_output])
}

/// Creates a [`TxHandler`] for the move_tx.
pub fn create_move_txhandler(
    deposit_outpoint: OutPoint,
    user_evm_address: EVMAddress,
    recovery_taproot_address: &Address<NetworkUnchecked>,
    nofn_xonly_pk: XOnlyPublicKey,
    user_takes_after: u32,
    bridge_amount_sats: Amount,
    network: bitcoin::Network,
) -> TxHandler {
    let (musig2_address, musig2_spendinfo) =
        create_taproot_address(&[], Some(nofn_xonly_pk), network);

    let tx_ins = create_tx_ins(vec![deposit_outpoint]);

    // let anyone_can_spend_txout = builder::script::anyone_can_spend_txout();
    // let move_txout = TxOut {
    //     value: bridge_amount_sats - anyone_can_spend_txout.value,
    //     script_pubkey: musig2_address.script_pubkey(),
    // };

    // let move_tx = create_btc_tx(tx_ins, vec![move_txout, anyone_can_spend_txout]);

    let anchor_output = builder::script::anchor_output();
    let move_txout = TxOut {
        value: bridge_amount_sats,
        script_pubkey: musig2_address.script_pubkey(),
    };

    let move_tx = create_btc_tx(tx_ins, vec![move_txout, anchor_output]);

    let (deposit_address, deposit_taproot_spend_info) = builder::address::generate_deposit_address(
        nofn_xonly_pk,
        recovery_taproot_address,
        user_evm_address,
        bridge_amount_sats,
        network,
        user_takes_after,
    );

    let prevouts = vec![TxOut {
        script_pubkey: deposit_address.script_pubkey(),
        value: bridge_amount_sats,
    }];

    let deposit_script = vec![builder::script::create_deposit_script(
        nofn_xonly_pk,
        user_evm_address,
        bridge_amount_sats,
    )];

    TxHandler {
        txid: move_tx.compute_txid(),
        tx: move_tx,
        prevouts,
        prev_scripts: vec![deposit_script],
        prev_taproot_spend_infos: vec![Some(deposit_taproot_spend_info)],
        out_scripts: vec![vec![], vec![]],
        out_taproot_spend_infos: vec![Some(musig2_spendinfo), None],
    }
}

// TODO: this function is outdated, delete after updating operator new_deposit()
/// Creates [`TxHandler`] of the kickoff_tx for the operator.
pub fn create_kickoff_utxo_txhandler(
    funding_utxo: &UTXO, // Make sure this comes from the operator's address.
    nofn_xonly_pk: XOnlyPublicKey,
    operator_xonly_pk: XOnlyPublicKey,
    network: bitcoin::Network,
    num_kickoff_utxos_per_tx: usize,
) -> TxHandler {
    // Here, we are calculating the minimum relay fee for the kickoff tx based on the number of kickoff utxos per tx.
    // The formula is: 154 + 43 * num_kickoff_utxos_per_tx where
    // 154 = (Signature as witness, 66 bytes + 2 bytes from flags) / 4
    // + 43 * 2 from change and anyone can spend txouts
    // + 41 from the single input (32 + 8 + 1)
    // 4 + 4 + 1 + 1 from locktime, version, and VarInt bases of
    // the number of inputs and outputs.
    let kickoff_tx_min_relay_fee = match num_kickoff_utxos_per_tx {
        0..=250 => 154 + 43 * num_kickoff_utxos_per_tx, // Handles all values from 0 to 250
        _ => 156 + 43 * num_kickoff_utxos_per_tx,       // Handles all other values
    };

    //  = 154 + 43 * num_kickoff_utxos_per_tx;
    let tx_ins = create_tx_ins(vec![funding_utxo.outpoint]);
    let musig2_and_operator_script = builder::script::create_musig2_and_operator_multisig_script(
        nofn_xonly_pk,
        operator_xonly_pk,
    );
    let (musig2_and_operator_address, _) =
        builder::address::create_taproot_address(&[musig2_and_operator_script], None, network);
    let operator_address = Address::p2tr(&SECP, operator_xonly_pk, None, network);
    let change_amount = funding_utxo.txout.value
        - Amount::from_sat(KICKOFF_UTXO_AMOUNT_SATS.to_sat() * num_kickoff_utxos_per_tx as u64)
        // - builder::script::anyone_can_spend_txout().value
        - builder::script::anchor_output().value
        - Amount::from_sat(kickoff_tx_min_relay_fee as u64);
    tracing::debug!("Change amount: {:?}", change_amount);
    let mut tx_outs_raw = vec![
        (
            KICKOFF_UTXO_AMOUNT_SATS,
            musig2_and_operator_address.script_pubkey(),
        );
        num_kickoff_utxos_per_tx
    ];

    tx_outs_raw.push((change_amount, operator_address.script_pubkey()));
    // tx_outs_raw.push((
    //     builder::script::anyone_can_spend_txout().value,
    //     builder::script::anyone_can_spend_txout().script_pubkey,
    // ));
    tx_outs_raw.push((
        builder::script::anchor_output().value,
        builder::script::anchor_output().script_pubkey,
    ));
    let tx_outs = create_tx_outs(tx_outs_raw);
    let tx = create_btc_tx(tx_ins, tx_outs);
    let prevouts = vec![funding_utxo.txout.clone()];
    let scripts = vec![vec![]];
    let taproot_spend_infos = vec![];
    TxHandler {
        txid: tx.compute_txid(),
        tx,
        prevouts,
        prev_scripts: scripts,
        prev_taproot_spend_infos: taproot_spend_infos,
        // placeholders
        out_scripts: vec![],
        out_taproot_spend_infos: vec![],
    }
}

pub fn create_kickoff_txhandler(
    sequential_collateral_txhandler: &TxHandler,
    kickoff_idx: usize,
    nofn_xonly_pk: XOnlyPublicKey,
    operator_xonly_pk: XOnlyPublicKey,
    move_txid: Txid,
    operator_idx: usize,
    network: Network,
) -> TxHandler {
    let tx_ins = create_tx_ins(vec![OutPoint {
        txid: sequential_collateral_txhandler.txid,
        vout: 2 + kickoff_idx as u32,
    }]);
    let operator_1week =
        builder::script::generate_relative_timelock_script(operator_xonly_pk, 7 * 24 * 6);
    let operator_2week =
        builder::script::generate_relative_timelock_script(operator_xonly_pk, 2 * 7 * 24 * 6);
    let nofn_3week =
        builder::script::generate_relative_timelock_script(nofn_xonly_pk, 3 * 7 * 24 * 6);

    let (nofn_or_operator_1week, nofn_or_operator_1week_spend) =
        builder::address::create_taproot_address(
            &[operator_1week.clone()],
            Some(nofn_xonly_pk),
            network,
        );

    let (nofn_or_operator_2week, nofn_or_operator_2week_spend) =
        builder::address::create_taproot_address(
            &[operator_2week.clone()],
            Some(nofn_xonly_pk),
            network,
        );

    let (nofn_or_nofn_3week, nofn_or_nofn_3week_spend) = builder::address::create_taproot_address(
        &[nofn_3week.clone()],
        Some(nofn_xonly_pk),
        network,
    );

    let (nofn_taproot_address, nofn_taproot_spend) =
        builder::address::create_musig2_address(nofn_xonly_pk, network);

    let mut tx_outs = create_tx_outs(vec![
        (MIN_TAPROOT_AMOUNT, nofn_taproot_address.script_pubkey()),
        (MIN_TAPROOT_AMOUNT, nofn_or_operator_1week.script_pubkey()),
        (MIN_TAPROOT_AMOUNT, nofn_or_operator_2week.script_pubkey()),
        (MIN_TAPROOT_AMOUNT, nofn_or_nofn_3week.script_pubkey()),
    ]);
    // tx_outs.push(builder::script::anyone_can_spend_txout());
    tx_outs.push(builder::script::anchor_output());

    let mut op_return_script = move_txid.to_byte_array().to_vec();
    op_return_script.extend(utils::usize_to_var_len_bytes(operator_idx));
    let mut push_bytes = PushBytesBuf::new();
    push_bytes.extend_from_slice(&op_return_script).unwrap();
    let op_return_txout = builder::script::op_return_txout(push_bytes);
    tx_outs.push(op_return_txout);

    let tx = create_btc_tx(tx_ins, tx_outs);

    TxHandler {
        txid: tx.compute_txid(),
        tx,
        prevouts: vec![sequential_collateral_txhandler.tx.output[2 + kickoff_idx].clone()],
        prev_scripts: vec![sequential_collateral_txhandler.out_scripts[2 + kickoff_idx].clone()],
        prev_taproot_spend_infos: vec![sequential_collateral_txhandler.out_taproot_spend_infos
            [2 + kickoff_idx]
            .clone()],
        out_scripts: vec![
            vec![],
            vec![operator_1week],
            vec![operator_2week],
            vec![nofn_3week],
            vec![],
            vec![],
        ],
        out_taproot_spend_infos: vec![
            Some(nofn_taproot_spend),
            Some(nofn_or_operator_1week_spend),
            Some(nofn_or_operator_2week_spend),
            Some(nofn_or_nofn_3week_spend),
            None,
            None,
        ],
    }
}

/// Creates a [`TxHandler`] for the watchtower challenge page transaction.
pub fn create_watchtower_challenge_kickoff_txhandler(
    kickoff_tx_handler: &TxHandler,
    num_watchtowers: u32,
    watchtower_xonly_pks: &[XOnlyPublicKey],
    watchtower_wots: Vec<Vec<[u8; 20]>>,
    network: bitcoin::Network,
) -> TxHandler {
    let tx_ins = create_tx_ins(vec![OutPoint {
        txid: kickoff_tx_handler.txid,
        vout: 0,
    }]);

    let verifier =
        winternitz::Winternitz::<winternitz::ListpickVerifier, winternitz::TabledConverter>::new();
    let wots_params = winternitz::Parameters::new(240, 4);

    let mut scripts: Vec<Vec<ScriptBuf>> = Vec::new();
    let mut spendinfos: Vec<Option<TaprootSpendInfo>> = Vec::new();

    let mut tx_outs = (0..num_watchtowers)
        .map(|i| {
            let mut x =
                verifier.checksig_verify(&wots_params, watchtower_wots[i as usize].as_ref());
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
    // tx_outs.push(builder::script::anyone_can_spend_txout());
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

pub fn create_watchtower_challenge_txhandler(
    wcp_txhandler: &TxHandler,
    watchtower_idx: usize,
    operator_unlock_hash: &[u8; 20],
    nofn_xonly_pk: XOnlyPublicKey,
    operator_xonly_pk: XOnlyPublicKey,
    network: bitcoin::Network,
) -> TxHandler {
    let tx_ins = create_tx_ins(vec![OutPoint {
        txid: wcp_txhandler.txid,
        vout: watchtower_idx as u32,
    }]);

    let nofn_1week = builder::script::generate_relative_timelock_script(nofn_xonly_pk, 7 * 24 * 6);
    let operator_with_preimage =
        builder::script::actor_with_preimage_script(operator_xonly_pk, operator_unlock_hash);
    let (nofn_or_nofn_1week, nofn_or_nofn_1week_spend) = builder::address::create_taproot_address(
        &[operator_with_preimage.clone(), nofn_1week.clone()],
        None,
        network,
    );

    let tx_outs = vec![
        TxOut {
            value: Amount::from_sat(1000), // TODO: Hand calculate this
            script_pubkey: nofn_or_nofn_1week.script_pubkey(),
        },
        // builder::script::anyone_can_spend_txout(),
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
        out_scripts: vec![vec![operator_with_preimage, nofn_1week], vec![]],
        out_taproot_spend_infos: vec![Some(nofn_or_nofn_1week_spend), None],
    }
}

pub fn create_operator_challenge_nack_txhandler(
    watchtower_challenge_txhandler: &TxHandler,
    kickoff_txhandler: &TxHandler,
) -> TxHandler {
    let tx_ins = create_tx_ins(vec![
        OutPoint {
            txid: watchtower_challenge_txhandler.txid,
            vout: 0,
        },
        OutPoint {
            txid: kickoff_txhandler.txid,
            vout: 2,
        },
    ]);
    // let tx_outs = vec![builder::script::anyone_can_spend_txout()];
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

pub fn create_assert_begin_txhandler(
    kickoff_txhandler: &TxHandler,
    assert_tx_addrs: &Vec<ScriptBuf>,
    _network: bitcoin::Network,
) -> TxHandler {
    let tx_ins: Vec<TxIn> = create_tx_ins(vec![OutPoint {
        txid: kickoff_txhandler.txid,
        vout: 2,
    }]);

    let mut scripts: Vec<Vec<ScriptBuf>> = Vec::new();
    let mut spendinfos: Vec<Option<TaprootSpendInfo>> = Vec::new();

    let mut txouts = vec![];
    for i in 0..PARALLEL_ASSERT_TX_CHAIN_SIZE {
        txouts.push(TxOut {
            value: MIN_TAPROOT_AMOUNT, // Minimum amount for a taproot output
            script_pubkey: assert_tx_addrs[i].clone(),
        });
    }
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

pub fn create_mini_assert_tx(
    prev_txid: Txid,
    prev_vout: u32,
    out_script: ScriptBuf,
    _network: bitcoin::Network,
) -> Transaction {
    let tx_ins = create_tx_ins(vec![OutPoint {
        txid: prev_txid,
        vout: prev_vout,
    }]);

    let tx_outs = vec![
        TxOut {
            value: Amount::from_sat(330),
            script_pubkey: out_script,
        },
        builder::script::anchor_output(),
    ];

    create_btc_tx(tx_ins, tx_outs)
}

pub fn create_assert_end_txhandler(
    kickoff_txhandler: &TxHandler,
    assert_begin_txhandler: &TxHandler,
    assert_tx_addrs: &Vec<ScriptBuf>,
    root_hash: &[u8; 32],
    nofn_xonly_pk: XOnlyPublicKey,
    public_input_wots: Vec<[u8; 20]>,
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
    for i in 0..PARALLEL_ASSERT_TX_CHAIN_SIZE {
        txins.push(OutPoint {
            txid: last_mini_assert_txid[i],
            vout: 0,
        });
    }
    txins.push(OutPoint {
        txid: kickoff_txhandler.txid,
        vout: 3,
    });

    let disprove_taproot_spend_info = TaprootBuilder::new()
        .add_hidden_node(0, TapNodeHash::from_slice(root_hash).unwrap())
        .unwrap()
        .finalize(&SECP, nofn_xonly_pk)
        .unwrap();

    let disprove_address = Address::p2tr(
        &SECP,
        nofn_xonly_pk,
        disprove_taproot_spend_info.merkle_root(),
        network,
    );

    let nofn_1week = builder::script::generate_relative_timelock_script(nofn_xonly_pk, 7 * 24 * 6);
    let nofn_2week =
        builder::script::generate_relative_timelock_script(nofn_xonly_pk, 2 * 7 * 24 * 6);
    let (connector_addr, connector_spend) = builder::address::create_taproot_address(
        &[nofn_1week.clone(), nofn_2week.clone()],
        None,
        network,
    );
    let tx_outs = vec![
        TxOut {
            value: MIN_TAPROOT_AMOUNT,
            script_pubkey: disprove_address.script_pubkey(),
        },
        TxOut {
            value: MIN_TAPROOT_AMOUNT,
            script_pubkey: connector_addr.script_pubkey(),
        },
        builder::script::anchor_output(),
    ];

    let assert_end_tx = create_btc_tx(create_tx_ins(txins), tx_outs);

    let mut prevouts = (0..PARALLEL_ASSERT_TX_CHAIN_SIZE)
        .map(|i| TxOut {
            value: MIN_TAPROOT_AMOUNT,
            script_pubkey: disprove_address.script_pubkey(), // TODO: this is wrong
        })
        .collect::<Vec<_>>();
    prevouts.push(kickoff_txhandler.tx.output[3].clone());

    let mut scripts = (0..NUM_INTERMEDIATE_STEPS)
        .map(|i| vec![]) // TODO: Add actual scripts here
        .collect::<Vec<_>>();
    scripts.push(kickoff_txhandler.out_scripts[3].clone());

    let mut prev_taproot_spend_infos = (0..NUM_INTERMEDIATE_STEPS)
        .map(|i| None) // TODO: Add actual spend info here
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

pub fn create_disprove_timeout_txhandler(
    assert_end_txhandler: &TxHandler,
    operator_xonly_pk: XOnlyPublicKey,
    network: bitcoin::Network,
) -> TxHandler {
    let tx_ins = create_tx_ins(vec![
        OutPoint {
            txid: assert_end_txhandler.txid,
            vout: 0,
        },
        OutPoint {
            txid: assert_end_txhandler.txid,
            vout: 1,
        },
    ]);

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

pub fn create_already_disproved_txhandler(
    assert_end_txhandler: &TxHandler,
    sequential_collateral_txhandler: &TxHandler,
) -> TxHandler {
    let tx_ins = create_tx_ins(vec![
        OutPoint {
            txid: assert_end_txhandler.txid,
            vout: 1,
        },
        OutPoint {
            txid: sequential_collateral_txhandler.txid,
            vout: 0,
        },
    ]);

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

pub fn create_disprove_txhandler(
    assert_end_txhandler: &TxHandler,
    sequential_collateral_txhandler: &TxHandler,
) -> TxHandler {
    let tx_ins = create_tx_ins(vec![
        OutPoint {
            txid: assert_end_txhandler.txid,
            vout: 0,
        },
        OutPoint {
            txid: sequential_collateral_txhandler.txid,
            vout: 0,
        },
    ]);

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

pub fn create_challenge_txhandler(
    kickoff_txhandler: &TxHandler,
    operator_reimbursement_address: &bitcoin::Address,
) -> TxHandler {
    let tx_ins = create_tx_ins(vec![OutPoint {
        txid: kickoff_txhandler.txid,
        vout: 1,
    }]);

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

pub fn create_start_happy_reimburse_txhandler(
    kickoff_txhandler: &TxHandler,
    operator_xonly_pk: XOnlyPublicKey,
    network: bitcoin::Network,
) -> TxHandler {
    let tx_ins = create_tx_ins(vec![
        OutPoint {
            txid: kickoff_txhandler.txid,
            vout: 1,
        },
        OutPoint {
            txid: kickoff_txhandler.txid,
            vout: 3,
        },
    ]);

    let (op_address, op_spend) = create_taproot_address(&[], Some(operator_xonly_pk), network);

    let tx_outs = vec![
        TxOut {
            value: MIN_TAPROOT_AMOUNT,
            script_pubkey: op_address.script_pubkey(),
        },
        builder::script::anchor_output(),
    ];

    let happy_reimburse_tx = create_btc_tx(tx_ins, tx_outs);

    TxHandler {
        txid: happy_reimburse_tx.compute_txid(),
        tx: happy_reimburse_tx,
        prevouts: vec![
            kickoff_txhandler.tx.output[1].clone(),
            kickoff_txhandler.tx.output[3].clone(),
        ],
        prev_scripts: vec![
            kickoff_txhandler.out_scripts[1].clone(),
            kickoff_txhandler.out_scripts[3].clone(),
        ],
        prev_taproot_spend_infos: vec![
            kickoff_txhandler.out_taproot_spend_infos[1].clone(),
            kickoff_txhandler.out_taproot_spend_infos[3].clone(),
        ],
        out_scripts: vec![vec![], vec![]],
        out_taproot_spend_infos: vec![Some(op_spend), None],
    }
}

pub fn create_happy_reimburse_txhandler(
    move_txhandler: &TxHandler,
    start_happy_reimburse_txhandler: &TxHandler,
    reimburse_generator_txhandler: &TxHandler,
    kickoff_idx: usize,
    operator_reimbursement_address: &bitcoin::Address,
) -> TxHandler {
    let tx_ins = create_tx_ins(vec![
        OutPoint {
            txid: move_txhandler.txid,
            vout: 0,
        },
        OutPoint {
            txid: start_happy_reimburse_txhandler.txid,
            vout: 0,
        },
        OutPoint {
            txid: reimburse_generator_txhandler.txid,
            vout: 1 + kickoff_idx as u32,
        },
    ]);

    let anchor_txout = builder::script::anchor_output();
    let tx_outs = vec![
        TxOut {
            // value in move_tx currently (bridge amount)
            value: move_txhandler.tx.output[0].value,
            script_pubkey: operator_reimbursement_address.script_pubkey(),
        },
        anchor_txout.clone(),
    ];

    let happy_reimburse_tx = create_btc_tx(tx_ins, tx_outs);

    TxHandler {
        txid: happy_reimburse_tx.compute_txid(),
        tx: happy_reimburse_tx,
        prevouts: vec![
            move_txhandler.tx.output[0].clone(),
            start_happy_reimburse_txhandler.tx.output[0].clone(),
            reimburse_generator_txhandler.tx.output[1 + kickoff_idx].clone(),
        ],
        prev_scripts: vec![
            move_txhandler.out_scripts[0].clone(),
            start_happy_reimburse_txhandler.out_scripts[0].clone(),
            reimburse_generator_txhandler.out_scripts[1 + kickoff_idx].clone(),
        ],
        prev_taproot_spend_infos: vec![
            move_txhandler.out_taproot_spend_infos[0].clone(),
            start_happy_reimburse_txhandler.out_taproot_spend_infos[0].clone(),
            reimburse_generator_txhandler.out_taproot_spend_infos[1 + kickoff_idx].clone(),
        ],
        out_scripts: vec![vec![], vec![]],
        out_taproot_spend_infos: vec![None, None],
    }
}

pub fn create_reimburse_txhandler(
    move_txhandler: &TxHandler,
    disprove_timeout_txhandler: &TxHandler,
    reimburse_generator_txhandler: &TxHandler,
    kickoff_idx: usize,
    operator_reimbursement_address: &bitcoin::Address,
) -> TxHandler {
    let tx_ins = create_tx_ins(vec![
        OutPoint {
            txid: move_txhandler.txid,
            vout: 0,
        },
        OutPoint {
            txid: disprove_timeout_txhandler.txid,
            vout: 0,
        },
        OutPoint {
            txid: reimburse_generator_txhandler.txid,
            vout: 1 + kickoff_idx as u32,
        },
    ]);

    let tx_outs = vec![
        TxOut {
            // value in move_tx currently (bridge amount)
            value: move_txhandler.tx.output[0].value,
            script_pubkey: operator_reimbursement_address.script_pubkey(),
        },
        builder::script::anchor_output(),
    ];

    let reimburse_tx = create_btc_tx(tx_ins, tx_outs);

    TxHandler {
        txid: reimburse_tx.compute_txid(),
        tx: reimburse_tx,
        prevouts: vec![
            move_txhandler.tx.output[0].clone(),
            disprove_timeout_txhandler.tx.output[0].clone(),
            reimburse_generator_txhandler.tx.output[1 + kickoff_idx].clone(),
        ],
        prev_scripts: vec![
            move_txhandler.out_scripts[0].clone(),
            disprove_timeout_txhandler.out_scripts[0].clone(),
            reimburse_generator_txhandler.out_scripts[1 + kickoff_idx].clone(),
        ],
        prev_taproot_spend_infos: vec![
            move_txhandler.out_taproot_spend_infos[0].clone(),
            disprove_timeout_txhandler.out_taproot_spend_infos[0].clone(),
            reimburse_generator_txhandler.out_taproot_spend_infos[1 + kickoff_idx].clone(),
        ],
        out_scripts: vec![vec![], vec![]],
        out_taproot_spend_infos: vec![None, None],
    }
}

pub fn create_kickoff_timeout_txhandler(
    kickoff_tx_handler: &TxHandler,
    sequential_collateral_txhandler: &TxHandler,
    network: Network,
) -> TxHandler {
    let tx_ins = create_tx_ins(vec![
        OutPoint {
            txid: kickoff_tx_handler.txid,
            vout: 3,
        },
        OutPoint {
            txid: sequential_collateral_txhandler.txid,
            vout: 0,
        },
    ]);
    let (dust_address, _) = create_taproot_address(&[], None, network);
    let dust_output = TxOut {
        value: Amount::from_sat(330),
        script_pubkey: dust_address.script_pubkey(),
    };
    let anchor_output = builder::script::anchor_output();
    let tx_outs = vec![dust_output, anchor_output];
    let kickoff_timeout_tx = create_btc_tx(tx_ins, tx_outs);
    TxHandler {
        txid: kickoff_timeout_tx.compute_txid(),
        tx: kickoff_timeout_tx,
        prevouts: vec![
            kickoff_tx_handler.tx.output[3].clone(),
            sequential_collateral_txhandler.tx.output[0].clone(),
        ],
        prev_scripts: vec![
            kickoff_tx_handler.out_scripts[3].clone(),
            sequential_collateral_txhandler.out_scripts[0].clone(),
        ],
        prev_taproot_spend_infos: vec![
            kickoff_tx_handler.out_taproot_spend_infos[3].clone(),
            sequential_collateral_txhandler.out_taproot_spend_infos[0].clone(),
        ],
        out_scripts: vec![vec![], vec![]],
        out_taproot_spend_infos: vec![None, None],
    }
}

// TODO: outdated, delete after changing functions it is used in
pub fn create_slash_or_take_tx(
    deposit_outpoint: OutPoint,
    kickoff_utxo: UTXO,
    operator_xonly_pk: XOnlyPublicKey,
    operator_idx: usize,
    nofn_xonly_pk: XOnlyPublicKey,
    network: bitcoin::Network,
    _user_takes_after: u32,
    operator_takes_after: u32,
    bridge_amount_sats: Amount,
) -> TxHandler {
    // First recreate the move_tx and move_txid. We can give dummy values for some of the parameters since we are only interested in txid.
    let move_tx = create_move_tx(deposit_outpoint, nofn_xonly_pk, bridge_amount_sats, network);
    let move_txid = move_tx.compute_txid();

    let (kickoff_utxo_address, kickoff_utxo_spend_info) =
        builder::address::create_kickoff_address(nofn_xonly_pk, operator_xonly_pk, network);
    // tracing::debug!(
    //     "kickoff_utxo_script_pubkey: {:?}",
    //     kickoff_utxo_address.script_pubkey()
    // );
    // tracing::debug!("kickoff_utxo_spend_info: {:?}", kickoff_utxo_spend_info);
    // tracing::debug!("kickoff_utxooo: {:?}", kickoff_utxo);
    let musig2_and_operator_script = builder::script::create_musig2_and_operator_multisig_script(
        nofn_xonly_pk,
        operator_xonly_pk,
    );
    // Sanity check
    tracing::debug!(
        "kickoff_utxo_script_pubkey: {:?}",
        kickoff_utxo_address.script_pubkey()
    );
    tracing::debug!(
        "kickoff_utxo_script_pubkey: {:?}",
        kickoff_utxo.txout.script_pubkey
    );
    tracing::debug!("Operator index: {:?}", operator_idx);
    tracing::debug!("Operator xonly pk: {:?}", operator_xonly_pk);
    tracing::debug!("Deposit OutPoint: {:?}", deposit_outpoint);
    assert!(kickoff_utxo_address.script_pubkey() == kickoff_utxo.txout.script_pubkey);
    let ins = create_tx_ins(vec![kickoff_utxo.outpoint]);
    let relative_timelock_script = builder::script::generate_relative_timelock_script(
        operator_xonly_pk,
        operator_takes_after as i64,
    );
    let (slash_or_take_address, _) = builder::address::create_taproot_address(
        &[relative_timelock_script.clone()],
        Some(nofn_xonly_pk),
        network,
    );
    let mut op_return_script = move_txid.to_byte_array().to_vec();
    op_return_script.extend(utils::usize_to_var_len_bytes(operator_idx));
    let mut push_bytes = PushBytesBuf::new();
    push_bytes.extend_from_slice(&op_return_script).unwrap();
    let op_return_txout = builder::script::op_return_txout(push_bytes);
    let outs = vec![
        TxOut {
            value: kickoff_utxo.txout.value - Amount::from_sat(330),
            script_pubkey: slash_or_take_address.script_pubkey(),
        },
        // builder::script::anyone_can_spend_txout(),
        builder::script::anchor_output(),
        op_return_txout,
    ];
    let tx = create_btc_tx(ins, outs);
    let prevouts = vec![kickoff_utxo.txout.clone()];
    let scripts = vec![vec![musig2_and_operator_script]];
    tracing::debug!("slash_or_take_tx weight: {:?}", tx.weight());
    TxHandler {
        txid: tx.compute_txid(),
        tx,
        prevouts,
        prev_scripts: scripts,
        prev_taproot_spend_infos: vec![Some(kickoff_utxo_spend_info)],
        // just placeholders below
        out_scripts: vec![vec![], vec![], vec![]],
        out_taproot_spend_infos: vec![None, None, None],
    }
}

// TODO: outdated
pub fn create_operator_takes_tx(
    bridge_fund_outpoint: OutPoint,
    slash_or_take_utxo: UTXO,
    operator_xonly_pk: XOnlyPublicKey,
    nofn_xonly_pk: XOnlyPublicKey,
    network: bitcoin::Network,
    operator_takes_after: u32,
    bridge_amount_sats: Amount,
    operator_wallet_address: Address<NetworkUnchecked>,
) -> TxHandler {
    let operator_wallet_address_checked = operator_wallet_address.require_network(network).unwrap();
    let mut ins = create_tx_ins(vec![bridge_fund_outpoint]);
    ins.extend(create_tx_ins_with_sequence(
        vec![slash_or_take_utxo.outpoint],
        operator_takes_after as u16,
    ));

    let (musig2_address, musig2_spend_info) =
        builder::address::create_musig2_address(nofn_xonly_pk, network);

    let relative_timelock_script = builder::script::generate_relative_timelock_script(
        operator_xonly_pk,
        operator_takes_after as i64,
    );
    let (slash_or_take_address, slash_or_take_spend_info) =
        builder::address::create_taproot_address(
            &[relative_timelock_script.clone()],
            Some(nofn_xonly_pk),
            network,
        );

    // Sanity check TODO: No asserts outside of tests
    assert!(slash_or_take_address.script_pubkey() == slash_or_take_utxo.txout.script_pubkey);

    let outs = vec![
        TxOut {
            value: slash_or_take_utxo.txout.value + bridge_amount_sats
                // - builder::script::anyone_can_spend_txout().value
                // - builder::script::anyone_can_spend_txout().value,
                - builder::script::anchor_output().value
                - builder::script::anchor_output().value,
            script_pubkey: operator_wallet_address_checked.script_pubkey(),
        },
        // builder::script::anyone_can_spend_txout(),
        builder::script::anchor_output(),
    ];
    let tx = create_btc_tx(ins, outs);
    let prevouts = vec![
        TxOut {
            script_pubkey: musig2_address.script_pubkey(),
            value: bridge_amount_sats
                // - builder::script::anyone_can_spend_txout().value,
                - builder::script::anchor_output().value,
        },
        slash_or_take_utxo.txout,
    ];
    let scripts = vec![vec![], vec![relative_timelock_script]];
    let taproot_spend_infos = vec![Some(musig2_spend_info), Some(slash_or_take_spend_info)];
    TxHandler {
        txid: tx.compute_txid(),
        tx,
        prevouts,
        prev_scripts: scripts,
        prev_taproot_spend_infos: taproot_spend_infos,
        // placeholders
        out_scripts: vec![vec![], vec![]],
        out_taproot_spend_infos: vec![None, None],
    }
}

/// Creates a Bitcoin V3 transaction with no locktime, using given inputs and
/// outputs.
pub fn create_btc_tx(tx_ins: Vec<TxIn>, tx_outs: Vec<TxOut>) -> bitcoin::Transaction {
    bitcoin::Transaction {
        version: bitcoin::transaction::Version(3),
        lock_time: absolute::LockTime::from_consensus(0),
        input: tx_ins,
        output: tx_outs,
    }
}

pub fn create_tx_ins(outpoints: Vec<OutPoint>) -> Vec<TxIn> {
    let mut tx_ins = Vec::new();

    for utxo in outpoints {
        tx_ins.push(TxIn {
            previous_output: utxo,
            sequence: bitcoin::transaction::Sequence::ENABLE_RBF_NO_LOCKTIME,
            script_sig: ScriptBuf::default(),
            witness: Witness::new(),
        });
    }

    tx_ins
}

pub fn create_tx_ins_with_sequence(utxos: Vec<OutPoint>, height: u16) -> Vec<TxIn> {
    let mut tx_ins = Vec::new();

    for utxo in utxos {
        tx_ins.push(TxIn {
            previous_output: utxo,
            sequence: bitcoin::transaction::Sequence::from_height(height),
            script_sig: ScriptBuf::default(),
            witness: Witness::new(),
        });
    }

    tx_ins
}

pub fn create_tx_outs(pairs: Vec<(Amount, ScriptBuf)>) -> Vec<TxOut> {
    let mut tx_outs = Vec::new();

    for pair in pairs {
        tx_outs.push(TxOut {
            value: pair.0,
            script_pubkey: pair.1,
        });
    }

    tx_outs
}

#[cfg(test)]
mod tests {
    use crate::{builder, utils::SECP};
    use bitcoin::{
        hashes::Hash, key::Keypair, secp256k1::SecretKey, Amount, OutPoint, Txid, XOnlyPublicKey,
    };
    use secp256k1::rand;

    #[test]
    fn create_move_tx() {
        let deposit_outpoint = OutPoint {
            txid: Txid::all_zeros(),
            vout: 0x45,
        };
        let secret_key = SecretKey::new(&mut rand::thread_rng());
        let nofn_xonly_pk =
            XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(&SECP, &secret_key)).0;
        let bridge_amount_sats = Amount::from_sat(0x1F45);
        let network = bitcoin::Network::Regtest;

        let move_tx =
            super::create_move_tx(deposit_outpoint, nofn_xonly_pk, bridge_amount_sats, network);

        assert_eq!(
            move_tx.input.first().unwrap().previous_output,
            deposit_outpoint
        );
        assert_eq!(
            move_tx.output.first().unwrap().script_pubkey,
            builder::address::create_musig2_address(nofn_xonly_pk, network)
                .0
                .script_pubkey()
        );
        assert_eq!(
            *move_tx.output.get(1).unwrap(),
            // builder::script::anyone_can_spend_txout()
            builder::script::anchor_output()
        );
    }

    // #[test]
    // fn create_watchtower_challenge_page_txhandler() {
    //     let network = bitcoin::Network::Regtest;
    //     let secret_key = SecretKey::new(&mut rand::thread_rng());
    //     let nofn_xonly_pk =
    //         XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(&SECP, &secret_key)).0;
    //     let (nofn_musig2_address, _) =
    //         builder::address::create_musig2_address(nofn_xonly_pk, network);

    //     let kickoff_outpoint = OutPoint {
    //         txid: Txid::all_zeros(),
    //         vout: 0x45,
    //     };
    //     let kickoff_utxo = UTXO {
    //         outpoint: kickoff_outpoint,
    //         txout: TxOut {
    //             value: Amount::from_int_btc(2),
    //             script_pubkey: nofn_musig2_address.script_pubkey(),
    //         },
    //     };

    //     let bridge_amount_sats = Amount::from_sat(0x1F45);
    //     let num_watchtowers = 3;

    //     let wcp_txhandler = super::create_watchtower_challenge_page_txhandler(
    //         &kickoff_utxo,
    //         nofn_xonly_pk,
    //         bridge_amount_sats,
    //         num_watchtowers,
    //         network,
    //     );
    //     assert_eq!(wcp_txhandler.tx.output.len(), num_watchtowers as usize);
    // }

    // #[test]
    // fn create_challenge_tx() {
    //     let operator_secret_key = SecretKey::new(&mut rand::thread_rng());
    //     let operator_xonly_pk =
    //         XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(&SECP, &operator_secret_key)).0;

    //     let kickoff_outpoint = OutPoint {
    //         txid: Txid::all_zeros(),
    //         vout: 0x45,
    //     };

    //     let challenge_tx = super::create_challenge_tx(kickoff_outpoint, operator_xonly_pk);
    //     assert_eq!(
    //         challenge_tx.tx_out(0).unwrap().value,
    //         Amount::from_int_btc(2)
    //     );
    //     assert_eq!(
    //         challenge_tx.tx_out(0).unwrap().script_pubkey,
    //         ScriptBuf::new_p2tr(&SECP, operator_xonly_pk, None)
    //     )
    // }
}
