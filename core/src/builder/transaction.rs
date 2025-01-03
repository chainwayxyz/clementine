//! # Transaction Builder
//!
//! Transaction builder provides useful functions for building typical Bitcoin
//! transactions.

use super::address::create_taproot_address;
use crate::builder;
use crate::constants::{NUM_DISPROVE_SCRIPTS, NUM_INTERMEDIATE_STEPS};
use crate::{utils, EVMAddress, UTXO};
use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::Hash;
use bitcoin::opcodes::all::OP_CHECKSIG;
use bitcoin::script::PushBytesBuf;
use bitcoin::{
    absolute, taproot::TaprootSpendInfo, Address, Amount, OutPoint, ScriptBuf, TxIn, TxOut, Witness,
};
use bitcoin::{Network, Transaction, Txid};
use bitvm::signatures::winternitz;
use secp256k1::XOnlyPublicKey;

/// Verbose information about a transaction.
#[derive(Debug, Clone)]
pub struct TxHandler {
    /// Transaction itself.
    pub tx: bitcoin::Transaction,
    /// Previous outputs in [`TxOut`] format.
    pub prevouts: Vec<TxOut>,
    /// Scripts for each previous output.
    pub scripts: Vec<Vec<ScriptBuf>>,
    /// Taproot spend information for each previous output.
    pub taproot_spend_infos: Vec<TaprootSpendInfo>,
}

// TODO: Move these constants to the config file
pub const MOVE_TX_MIN_RELAY_FEE: Amount = Amount::from_sat(190);
pub const SLASH_OR_TAKE_TX_MIN_RELAY_FEE: Amount = Amount::from_sat(240);
pub const OPERATOR_TAKES_TX_MIN_RELAY_FEE: Amount = Amount::from_sat(230);
pub const KICKOFF_UTXO_AMOUNT_SATS: Amount = Amount::from_sat(100_000);

/// TODO: Change this to correct value
pub const TIME_TX_MIN_RELAY_FEE: Amount = Amount::from_sat(350);
/// TODO: Change this to correct value
pub const TIME2_TX_MIN_RELAY_FEE: Amount = Amount::from_sat(350);
pub const KICKOFF_INPUT_AMOUNT: Amount = Amount::from_sat(100_000);
pub const OPERATOR_REIMBURSE_CONNECTOR_AMOUNT: Amount = Amount::from_sat(330);
pub const ANCHOR_AMOUNT: Amount = Amount::from_sat(330);
pub const OPERATOR_CHALLENGE_AMOUNT: Amount = Amount::from_sat(200_000_000);

/// Creates the `time_tx`. It will always use `input_txid`'s first vout as the input.
///
/// # Returns
///
/// A `time_tx` that has outputs of:
///
/// 1. Operator's Burn Connector
/// 2. Operator's Time Connector: timelocked utxo for operator for the entire withdrawal time
/// 3. Kickoff input utxo: this utxo will be the input for the kickoff tx
/// 4. P2Anchor: Anchor output for CPFP
pub fn create_time_tx(
    operator_xonly_pk: XOnlyPublicKey,
    input_txid: Txid,
    input_amount: Amount,
    timeout_block_count: i64,
    max_withdrawal_time_block_count: i64,
    network: bitcoin::Network,
) -> Transaction {
    let tx_ins = create_tx_ins(vec![OutPoint {
        txid: input_txid,
        vout: 0,
    }]);

    let max_withdrawal_time_locked_script = builder::script::generate_relative_timelock_script(
        operator_xonly_pk,
        max_withdrawal_time_block_count,
    );

    let timeout_block_count_locked_script =
        builder::script::generate_relative_timelock_script(operator_xonly_pk, timeout_block_count);

    let tx_outs = vec![
        TxOut {
            value: input_amount
                - OPERATOR_REIMBURSE_CONNECTOR_AMOUNT
                - KICKOFF_INPUT_AMOUNT
                - ANCHOR_AMOUNT
                - TIME_TX_MIN_RELAY_FEE,
            script_pubkey: create_taproot_address(&[], Some(operator_xonly_pk), network)
                .0
                .script_pubkey(),
        },
        TxOut {
            value: OPERATOR_REIMBURSE_CONNECTOR_AMOUNT,
            script_pubkey: create_taproot_address(
                &[max_withdrawal_time_locked_script],
                None,
                network,
            )
            .0
            .script_pubkey(),
        },
        TxOut {
            value: KICKOFF_INPUT_AMOUNT,
            script_pubkey: create_taproot_address(
                &[timeout_block_count_locked_script],
                Some(operator_xonly_pk),
                network,
            )
            .0
            .script_pubkey(),
        },
        builder::script::anyone_can_spend_txout(),
    ];

    create_btc_tx(tx_ins, tx_outs)
}

pub fn create_time2_tx(
    operator_xonly_pk: XOnlyPublicKey,
    time_txid: Txid,
    time_tx_input_amount: Amount,
    network: bitcoin::Network,
) -> Transaction {
    let tx_ins = create_tx_ins(vec![
        OutPoint {
            txid: time_txid,
            vout: 0,
        },
        OutPoint {
            txid: time_txid,
            vout: 1,
        },
    ]);

    let output_script_pubkey = create_taproot_address(&[], Some(operator_xonly_pk), network)
        .0
        .script_pubkey();

    let tx_outs = vec![
        TxOut {
            value: time_tx_input_amount
                - OPERATOR_REIMBURSE_CONNECTOR_AMOUNT
                - KICKOFF_INPUT_AMOUNT
                - ANCHOR_AMOUNT
                - TIME_TX_MIN_RELAY_FEE
                - ANCHOR_AMOUNT
                - TIME2_TX_MIN_RELAY_FEE,
            script_pubkey: output_script_pubkey.clone(),
        },
        TxOut {
            value: OPERATOR_REIMBURSE_CONNECTOR_AMOUNT,
            script_pubkey: output_script_pubkey,
        },
        builder::script::anyone_can_spend_txout(),
    ];
    create_btc_tx(tx_ins, tx_outs)
}

pub fn create_timeout_tx_handler(
    operator_xonly_pk: XOnlyPublicKey,
    time_txid: Txid,
    timeout_block_count: i64,
    network: bitcoin::Network,
) -> TxHandler {
    let tx_ins = create_tx_ins(vec![OutPoint {
        txid: time_txid,
        vout: 2,
    }]);

    let tx_outs = vec![builder::script::anyone_can_spend_txout()];

    let tx = create_btc_tx(tx_ins, tx_outs);

    let timeout_block_count_locked_script =
        builder::script::generate_relative_timelock_script(operator_xonly_pk, timeout_block_count);

    let (timeout_input_addr, ttimeout_input_taproot_spend_info) = create_taproot_address(
        &[timeout_block_count_locked_script.clone()],
        Some(operator_xonly_pk),
        network,
    );

    let prevouts = vec![TxOut {
        value: KICKOFF_INPUT_AMOUNT,
        script_pubkey: timeout_input_addr.script_pubkey(),
    }];
    let scripts = vec![vec![timeout_block_count_locked_script]];
    let taproot_spend_infos = vec![ttimeout_input_taproot_spend_info];
    TxHandler {
        tx,
        prevouts,
        scripts,
        taproot_spend_infos,
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

    let anyone_can_spend_txout = builder::script::anyone_can_spend_txout();
    let move_txout = TxOut {
        value: bridge_amount_sats - MOVE_TX_MIN_RELAY_FEE - anyone_can_spend_txout.value,
        script_pubkey: musig2_address.script_pubkey(),
    };

    create_btc_tx(tx_ins, vec![move_txout, anyone_can_spend_txout])
}

/// Creates a [`TxHandler`] for the move_tx.
pub fn create_move_tx_handler(
    deposit_outpoint: OutPoint,
    user_evm_address: EVMAddress,
    recovery_taproot_address: &Address<NetworkUnchecked>,
    nofn_xonly_pk: XOnlyPublicKey,
    network: bitcoin::Network,
    user_takes_after: u32,
    bridge_amount_sats: Amount,
) -> TxHandler {
    let move_tx = create_move_tx(deposit_outpoint, nofn_xonly_pk, bridge_amount_sats, network);

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
        tx: move_tx,
        prevouts,
        scripts: vec![deposit_script],
        taproot_spend_infos: vec![deposit_taproot_spend_info],
    }
}

/// Creates the kickoff_tx for the operator. It also returns the change utxo
pub fn create_kickoff_utxo_tx(
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
    let operator_address = Address::p2tr(&utils::SECP, operator_xonly_pk, None, network);
    let change_amount = funding_utxo.txout.value
        - Amount::from_sat(KICKOFF_UTXO_AMOUNT_SATS.to_sat() * num_kickoff_utxos_per_tx as u64)
        - builder::script::anyone_can_spend_txout().value
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
    tx_outs_raw.push((
        builder::script::anyone_can_spend_txout().value,
        builder::script::anyone_can_spend_txout().script_pubkey,
    ));
    let tx_outs = create_tx_outs(tx_outs_raw);
    let tx = create_btc_tx(tx_ins, tx_outs);
    let prevouts = vec![funding_utxo.txout.clone()];
    let scripts = vec![vec![]];
    let taproot_spend_infos = vec![];
    TxHandler {
        tx,
        prevouts,
        scripts,
        taproot_spend_infos,
    }
}

pub fn create_kickoff_tx(
    time_txid: Txid,
    nofn_xonly_pk: XOnlyPublicKey,
    operator_xonly_pk: XOnlyPublicKey,
    move_txid: Txid,
    operator_idx: usize,
    network: Network,
) -> Transaction {
    let tx_ins = create_tx_ins(vec![OutPoint {
        txid: time_txid,
        vout: 2,
    }]);
    let operator_1week =
        builder::script::generate_relative_timelock_script(operator_xonly_pk, 7 * 24 * 6);
    let operator_2week =
        builder::script::generate_relative_timelock_script(operator_xonly_pk, 2 * 7 * 24 * 6);
    let nofn_3week =
        builder::script::generate_relative_timelock_script(nofn_xonly_pk, 3 * 7 * 24 * 6);

    let (nofn_or_operator_1week, _) =
        builder::address::create_taproot_address(&[operator_1week], Some(nofn_xonly_pk), network);

    let (nofn_or_operator_2week, _) =
        builder::address::create_taproot_address(&[operator_2week], Some(nofn_xonly_pk), network);

    let nofn_or_nofn_3week =
        builder::address::create_taproot_address(&[nofn_3week], Some(nofn_xonly_pk), network).0;

    let (nofn_taproot_address, _) = builder::address::create_musig2_address(nofn_xonly_pk, network);

    // TODO: change to normal sats
    let mut tx_outs = create_tx_outs(vec![
        (
            KICKOFF_UTXO_AMOUNT_SATS,
            nofn_taproot_address.script_pubkey(),
        ),
        (
            KICKOFF_UTXO_AMOUNT_SATS,
            nofn_or_operator_1week.script_pubkey(),
        ),
        (
            KICKOFF_UTXO_AMOUNT_SATS,
            nofn_or_operator_2week.script_pubkey(),
        ),
        (KICKOFF_UTXO_AMOUNT_SATS, nofn_or_nofn_3week.script_pubkey()),
    ]);
    tx_outs.push(builder::script::anyone_can_spend_txout());

    let mut op_return_script = move_txid.to_byte_array().to_vec();
    op_return_script.extend(utils::usize_to_var_len_bytes(operator_idx));
    let mut push_bytes = PushBytesBuf::new();
    push_bytes.extend_from_slice(&op_return_script).unwrap();
    let op_return_txout = builder::script::op_return_txout(push_bytes);
    tx_outs.push(op_return_txout);

    create_btc_tx(tx_ins, tx_outs)
}

/// Creates a [`TxHandler`] for the watchtower challenge page transaction.
pub fn create_watchtower_challenge_page_txhandler(
    kickoff_txid: Txid,
    nofn_xonly_pk: XOnlyPublicKey,
    num_watchtowers: u32,
    watchtower_wots: Vec<Vec<[u8; 20]>>,
    network: bitcoin::Network,
) -> TxHandler {
    let (nofn_taproot_address, nofn_taproot_spend_info) =
        builder::address::create_musig2_address(nofn_xonly_pk, network);
    let tx_ins = create_tx_ins(vec![OutPoint {
        txid: kickoff_txid,
        vout: 0,
    }]);

    let verifier =
        winternitz::Winternitz::<winternitz::ListpickVerifier, winternitz::TabledConverter>::new();
    let wots_params = winternitz::Parameters::new(240, 4);

    let mut tx_outs = (0..num_watchtowers)
        .map(|i| {
            let mut x =
                verifier.checksig_verify(&wots_params, watchtower_wots[i as usize].as_ref());
            x = x.push_x_only_key(&nofn_xonly_pk);
            x = x.push_opcode(OP_CHECKSIG); // TODO: Add checksig in the beginning
            let x = x.compile();
            let (watchtower_challenge_addr, _) =
                builder::address::create_taproot_address(&[x], None, network);

            TxOut {
                value: Amount::from_sat(2000), // TOOD: Hand calculate this
                script_pubkey: watchtower_challenge_addr.script_pubkey(), // TODO: Add winternitz checks here
            }
        })
        .collect::<Vec<_>>();

    // add the anchor output
    tx_outs.push(builder::script::anyone_can_spend_txout());

    let wcptx = create_btc_tx(tx_ins, tx_outs);

    TxHandler {
        tx: wcptx,
        prevouts: vec![TxOut {
            script_pubkey: nofn_taproot_address.script_pubkey(),
            value: Amount::from_sat(2000 * num_watchtowers as u64 + 330 + 500), // TOOD: Hand calculate this
        }],
        scripts: vec![vec![]],
        taproot_spend_infos: vec![nofn_taproot_spend_info],
    }
}

pub fn create_watchtower_challenge_txhandler(
    wcp_txid: Txid,
    watchtower_idx: usize,
    watchtower_wots: Vec<[u8; 20]>,
    operator_unlock_hash: &[u8; 20],
    nofn_xonly_pk: XOnlyPublicKey,
    operator_xonly_pk: XOnlyPublicKey,
    network: bitcoin::Network,
) -> TxHandler {
    let tx_ins = create_tx_ins(vec![OutPoint {
        txid: wcp_txid,
        vout: watchtower_idx as u32,
    }]);

    let nofn_1week = builder::script::generate_relative_timelock_script(nofn_xonly_pk, 7 * 24 * 6);
    let operator_with_preimage =
        builder::script::actor_with_preimage_script(operator_xonly_pk, operator_unlock_hash);
    let (nofn_or_nofn_1week, _) = builder::address::create_taproot_address(
        &[operator_with_preimage, nofn_1week],
        None,
        network,
    );

    let tx_outs = vec![
        TxOut {
            value: Amount::from_sat(1000), // TODO: Hand calculate this
            script_pubkey: nofn_or_nofn_1week.script_pubkey(),
        },
        builder::script::anyone_can_spend_txout(),
    ];

    let wcptx2 = create_btc_tx(tx_ins, tx_outs);

    // Calculate prevouts:
    let verifier =
        winternitz::Winternitz::<winternitz::ListpickVerifier, winternitz::TabledConverter>::new();
    let wots_params = winternitz::Parameters::new(240, 4);

    let mut x = verifier.checksig_verify(&wots_params, watchtower_wots.as_ref());
    x = x.push_x_only_key(&nofn_xonly_pk);
    x = x.push_opcode(OP_CHECKSIG); // TODO: Add checksig in the beginning
    let watchtower_challenge_script = x.compile();
    let (watchtower_challenge_addr, watchtower_challenge_taproot_spend_info) =
        builder::address::create_taproot_address(
            &[watchtower_challenge_script.clone()],
            None,
            network,
        );

    let prevouts = vec![TxOut {
        value: Amount::from_sat(2000), // TOOD: Hand calculate this
        script_pubkey: watchtower_challenge_addr.script_pubkey(), // TODO: Add winternitz checks here
    }];
    TxHandler {
        tx: wcptx2,
        prevouts,
        scripts: vec![vec![watchtower_challenge_script]],
        taproot_spend_infos: vec![watchtower_challenge_taproot_spend_info],
    }
}

pub fn create_operator_challenge_nack_txhandler(
    watchtower_challenge_txid: Txid,
    time_txid: Txid,
    kickoff_txid: Txid,
    time_tx_amount: Amount,
    operator_unlock_hash: &[u8; 20],
    nofn_xonly_pk: XOnlyPublicKey,
    operator_xonly_pk: XOnlyPublicKey,
    network: bitcoin::Network,
) -> TxHandler {
    let tx_ins = create_tx_ins(vec![
        OutPoint {
            txid: watchtower_challenge_txid,
            vout: 0,
        },
        OutPoint {
            txid: kickoff_txid,
            vout: 2,
        },
        OutPoint {
            txid: time_txid,
            vout: 0,
        },
    ]);
    let tx_outs = vec![builder::script::anyone_can_spend_txout()];
    let challenge_nack_tx = create_btc_tx(tx_ins, tx_outs);

    // prevout1
    let nofn_1week = builder::script::generate_relative_timelock_script(nofn_xonly_pk, 7 * 24 * 6);
    let operator_with_preimage =
        builder::script::actor_with_preimage_script(operator_xonly_pk, operator_unlock_hash);
    let (nofn_or_nofn_1week, nofn_or_nofn_1week_taproot_spend_info) =
        builder::address::create_taproot_address(
            &[operator_with_preimage.clone(), nofn_1week.clone()],
            None,
            network,
        );

    // prevout2
    let operator_2week =
        builder::script::generate_relative_timelock_script(operator_xonly_pk, 2 * 7 * 24 * 6);
    let (nofn_or_operator_2week, nofn_or_operator_2week_taproot_spend_info) =
        builder::address::create_taproot_address(
            &[operator_2week.clone()],
            Some(nofn_xonly_pk),
            network,
        );

    let (operator_taproot_address, operator_taproot_spend_info) =
        builder::address::create_musig2_address(operator_xonly_pk, network);

    let prevouts = vec![
        TxOut {
            value: Amount::from_sat(1000), // TODO: Hand calculate this
            script_pubkey: nofn_or_nofn_1week.script_pubkey(),
        },
        TxOut {
            value: KICKOFF_UTXO_AMOUNT_SATS, // TODO: Hand calculate this
            script_pubkey: nofn_or_operator_2week.script_pubkey(),
        },
        TxOut {
            value: time_tx_amount,
            script_pubkey: operator_taproot_address.script_pubkey(),
        },
    ];

    TxHandler {
        tx: challenge_nack_tx,
        prevouts,
        scripts: vec![
            vec![operator_with_preimage, nofn_1week],
            vec![operator_2week],
            vec![],
        ],
        taproot_spend_infos: vec![
            nofn_or_nofn_1week_taproot_spend_info,
            nofn_or_operator_2week_taproot_spend_info,
            operator_taproot_spend_info,
        ],
    }
}

pub fn create_assert_begin_txhandler(
    kickoff_txid: Txid,
    nofn_xonly_pk: XOnlyPublicKey,
    operator_xonly_pk: XOnlyPublicKey,
    intermediate_wotss: Vec<Vec<[u8; 20]>>,
    network: bitcoin::Network,
) -> TxHandler {
    let tx_ins: Vec<TxIn> = create_tx_ins(vec![OutPoint {
        txid: kickoff_txid,
        vout: 2,
    }]);

    let mut txouts = vec![];
    let verifier =
        winternitz::Winternitz::<winternitz::ListpickVerifier, winternitz::TabledConverter>::new();
    let wots_params = winternitz::Parameters::new(40, 4);
    for intermediate_wots in intermediate_wotss.iter().take(NUM_INTERMEDIATE_STEPS) {
        // TODO: Is there a possibility that list going to be longer than NUM_INTERMEDIATE_STEPS?
        let mut x = verifier.checksig_verify(&wots_params, intermediate_wots);
        x = x.push_x_only_key(&operator_xonly_pk);
        x = x.push_opcode(OP_CHECKSIG); // TODO: Add checksig in the beginning
        let intermediate_script = x.compile();
        let (intermediate_addr, _) =
            builder::address::create_taproot_address(&[intermediate_script.clone()], None, network);

        txouts.push(TxOut {
            value: Amount::from_sat(660), // TOOD: Hand calculate this
            script_pubkey: intermediate_addr.script_pubkey(), // TODO: Add winternitz checks here
        });
    }
    txouts.push(builder::script::anyone_can_spend_txout());

    let assert_begin_tx = create_btc_tx(tx_ins, txouts);

    // Prevouts

    let operator_2week =
        builder::script::generate_relative_timelock_script(operator_xonly_pk, 2 * 7 * 24 * 6);
    let (nofn_or_operator_2week, nofn_or_operator_2week_taproot_spend_info) =
        builder::address::create_taproot_address(
            &[operator_2week.clone()],
            Some(nofn_xonly_pk),
            network,
        );

    TxHandler {
        tx: assert_begin_tx,
        prevouts: vec![TxOut {
            script_pubkey: nofn_or_operator_2week.script_pubkey(),
            value: KICKOFF_UTXO_AMOUNT_SATS,
        }],
        scripts: vec![vec![operator_2week]],
        taproot_spend_infos: vec![nofn_or_operator_2week_taproot_spend_info],
    }
}

pub fn create_mini_assert_tx(
    assert_begin_txid: Txid,
    operator_xonly_pk: XOnlyPublicKey,
    step_index: u32,
    network: bitcoin::Network,
) -> Transaction {
    let tx_ins = create_tx_ins(vec![OutPoint {
        txid: assert_begin_txid,
        vout: step_index,
    }]);

    let tx_outs = vec![
        TxOut {
            value: Amount::from_sat(330), // TOOD: Hand calculate this
            script_pubkey: builder::address::create_taproot_address(
                &[],
                Some(operator_xonly_pk),
                network,
            )
            .0
            .script_pubkey(),
        },
        builder::script::anyone_can_spend_txout(),
    ];

    create_btc_tx(tx_ins, tx_outs)
}

pub fn create_assert_end_txhandler(
    kickoff_txid: Txid,
    assert_begin_txid: Txid,
    nofn_xonly_pk: XOnlyPublicKey,
    operator_xonly_pk: XOnlyPublicKey,
    network: bitcoin::Network,
) -> TxHandler {
    let mut txins = (0..NUM_INTERMEDIATE_STEPS)
        .map(|i| {
            let mini_assert_tx =
                create_mini_assert_tx(assert_begin_txid, operator_xonly_pk, i as u32, network);
            OutPoint {
                txid: mini_assert_tx.compute_txid(),
                vout: 0,
            }
        })
        .collect::<Vec<_>>();

    txins.push(OutPoint {
        txid: kickoff_txid,
        vout: 3,
    });

    let mut disprove_scripts = vec![];
    for _ in 0..NUM_DISPROVE_SCRIPTS {
        disprove_scripts.push(builder::script::checksig_script(nofn_xonly_pk)); // TODO: ADD actual disprove scripts here
    }

    let (disprove_address, _disprove_taproot_spend_info) = builder::address::create_taproot_address(
        &disprove_scripts.clone(),
        Some(nofn_xonly_pk),
        network,
    );
    let tx_outs = vec![
        TxOut {
            value: Amount::from_sat(330), // TODO: Hand calculate this
            script_pubkey: disprove_address.script_pubkey(),
        },
        builder::script::anyone_can_spend_txout(),
    ];

    let assert_end_tx = create_btc_tx(create_tx_ins(txins), tx_outs);

    // prevouts

    let nofn_3week =
        builder::script::generate_relative_timelock_script(nofn_xonly_pk, 3 * 7 * 24 * 6);
    let (nofn_or_nofn_3week, nofn_or_nofn_3week_taproot_spend_info) =
        builder::address::create_taproot_address(
            &[nofn_3week.clone()],
            Some(nofn_xonly_pk),
            network,
        );

    let (operator_taproot_address, operator_taproot_spend_info) =
        builder::address::create_taproot_address(&[], Some(operator_xonly_pk), network);

    let mut prevouts = vec![
        TxOut {
            script_pubkey: operator_taproot_address.script_pubkey(),
            value: Amount::from_sat(330),
        };
        NUM_INTERMEDIATE_STEPS
    ];

    prevouts.push(TxOut {
        script_pubkey: nofn_or_nofn_3week.script_pubkey(),
        value: KICKOFF_UTXO_AMOUNT_SATS,
    });

    let mut scripts = vec![vec![]; NUM_INTERMEDIATE_STEPS];
    scripts.push(vec![nofn_3week]);

    let mut taproot_spend_infos = vec![operator_taproot_spend_info; NUM_INTERMEDIATE_STEPS];
    taproot_spend_infos.push(nofn_or_nofn_3week_taproot_spend_info);

    TxHandler {
        tx: assert_end_tx,
        prevouts,
        scripts,
        taproot_spend_infos,
    }
}

pub fn create_disprove_txhandler(
    assert_end_txid: Txid,
    time_txid: Txid,
    nofn_xonly_pk: XOnlyPublicKey,
    network: bitcoin::Network,
) -> TxHandler {
    let tx_ins = create_tx_ins(vec![
        OutPoint {
            txid: assert_end_txid,
            vout: 0,
        },
        OutPoint {
            txid: time_txid,
            vout: 0,
        },
    ]);

    let tx_outs = vec![builder::script::anyone_can_spend_txout()];

    let disprove_tx = create_btc_tx(tx_ins, tx_outs);

    let mut disprove_scripts = vec![];
    for _ in 0..NUM_DISPROVE_SCRIPTS {
        disprove_scripts.push(builder::script::checksig_script(nofn_xonly_pk)); // TODO: ADD actual disprove scripts here
    }
    let (disprove_address, disprove_taproot_spend_info) =
        builder::address::create_taproot_address(&disprove_scripts, Some(nofn_xonly_pk), network);
    let prevouts = vec![TxOut {
        value: Amount::from_sat(330), // TODO: Hand calculate this
        script_pubkey: disprove_address.script_pubkey(),
    }];

    TxHandler {
        tx: disprove_tx,
        prevouts,
        scripts: vec![disprove_scripts, vec![]],
        taproot_spend_infos: vec![disprove_taproot_spend_info],
    }
}

pub fn create_challenge_txhandler(
    kickoff_txid: Txid,
    nofn_xonly_pk: XOnlyPublicKey,
    operator_xonly_pk: XOnlyPublicKey,
    network: bitcoin::Network,
) -> TxHandler {
    let tx_ins = create_tx_ins(vec![OutPoint {
        txid: kickoff_txid,
        vout: 1,
    }]);

    let (operator_taproot_address, _) =
        builder::address::create_taproot_address(&[], Some(operator_xonly_pk), network);

    let tx_outs = vec![TxOut {
        value: OPERATOR_CHALLENGE_AMOUNT,
        script_pubkey: operator_taproot_address.script_pubkey(),
    }];

    let challenge_tx = create_btc_tx(tx_ins, tx_outs);

    let operator_1week =
        builder::script::generate_relative_timelock_script(operator_xonly_pk, 7 * 24 * 6);

    let (nofn_or_operator_1week, nofn_or_operator_1week_spend_info) =
        builder::address::create_taproot_address(
            &[operator_1week.clone()],
            Some(nofn_xonly_pk),
            network,
        );

    let prevouts = vec![TxOut {
        script_pubkey: nofn_or_operator_1week.script_pubkey(),
        value: KICKOFF_UTXO_AMOUNT_SATS,
    }];

    TxHandler {
        tx: challenge_tx,
        prevouts,
        scripts: vec![vec![operator_1week]],
        taproot_spend_infos: vec![nofn_or_operator_1week_spend_info],
    }
}

pub fn create_happy_reimburse_txhandler(
    move_txid: Txid,
    kickoff_txid: Txid,
    nofn_xonly_pk: XOnlyPublicKey,
    operator_xonly_pk: XOnlyPublicKey,
    bridge_amount_sats: Amount,
    network: bitcoin::Network,
) -> TxHandler {
    let tx_ins = create_tx_ins(vec![
        OutPoint {
            txid: move_txid,
            vout: 0,
        },
        OutPoint {
            txid: kickoff_txid,
            vout: 1,
        },
        OutPoint {
            txid: kickoff_txid,
            vout: 3,
        },
    ]);
    let (operator_taproot_address, _) =
        builder::address::create_taproot_address(&[], Some(operator_xonly_pk), network);
    let (nofn_taproot_address, nofn_taproot_address_spend) =
        builder::address::create_taproot_address(&[], Some(nofn_xonly_pk), network);

    let anyone_can_spend_txout = builder::script::anyone_can_spend_txout();

    let tx_outs = vec![
        TxOut {
            // value in create_move_tx currently
            value: bridge_amount_sats - MOVE_TX_MIN_RELAY_FEE - anyone_can_spend_txout.value,
            script_pubkey: operator_taproot_address.script_pubkey(),
        },
        anyone_can_spend_txout.clone(),
    ];

    let happy_reimburse_tx = create_btc_tx(tx_ins, tx_outs);

    let operator_1week =
        builder::script::generate_relative_timelock_script(operator_xonly_pk, 7 * 24 * 6);
    let nofn_3week =
        builder::script::generate_relative_timelock_script(nofn_xonly_pk, 3 * 7 * 24 * 6);

    let (nofn_or_operator_1week, nofn_or_operator_1week_spend) =
        builder::address::create_taproot_address(
            &[operator_1week.clone()],
            Some(nofn_xonly_pk),
            network,
        );

    let (nofn_or_nofn_3week, nofn_or_nofn_3week_spend) = builder::address::create_taproot_address(
        &[nofn_3week.clone()],
        Some(nofn_xonly_pk),
        network,
    );

    let prevouts = vec![
        TxOut {
            script_pubkey: nofn_taproot_address.script_pubkey(),
            value: bridge_amount_sats - MOVE_TX_MIN_RELAY_FEE - anyone_can_spend_txout.value,
        },
        TxOut {
            value: KICKOFF_UTXO_AMOUNT_SATS,
            script_pubkey: nofn_or_operator_1week.script_pubkey(),
        },
        TxOut {
            value: KICKOFF_UTXO_AMOUNT_SATS,
            script_pubkey: nofn_or_nofn_3week.script_pubkey(),
        },
    ];

    TxHandler {
        tx: happy_reimburse_tx,
        prevouts,
        scripts: vec![vec![], vec![operator_1week], vec![nofn_3week]],
        taproot_spend_infos: vec![
            nofn_taproot_address_spend,
            nofn_or_operator_1week_spend,
            nofn_or_nofn_3week_spend,
        ],
    }
}

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
            value: kickoff_utxo.txout.value
                - Amount::from_sat(330)
                - SLASH_OR_TAKE_TX_MIN_RELAY_FEE,
            script_pubkey: slash_or_take_address.script_pubkey(),
        },
        builder::script::anyone_can_spend_txout(),
        op_return_txout,
    ];
    let tx = create_btc_tx(ins, outs);
    let prevouts = vec![kickoff_utxo.txout.clone()];
    let scripts = vec![vec![musig2_and_operator_script]];
    tracing::debug!("slash_or_take_tx weight: {:?}", tx.weight());
    TxHandler {
        tx,
        prevouts,
        scripts,
        taproot_spend_infos: vec![kickoff_utxo_spend_info],
    }
}

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
                - MOVE_TX_MIN_RELAY_FEE
                - OPERATOR_TAKES_TX_MIN_RELAY_FEE
                - builder::script::anyone_can_spend_txout().value
                - builder::script::anyone_can_spend_txout().value,
            script_pubkey: operator_wallet_address_checked.script_pubkey(),
        },
        builder::script::anyone_can_spend_txout(),
    ];
    let tx = create_btc_tx(ins, outs);
    let prevouts = vec![
        TxOut {
            script_pubkey: musig2_address.script_pubkey(),
            value: bridge_amount_sats
                - MOVE_TX_MIN_RELAY_FEE
                - builder::script::anyone_can_spend_txout().value,
        },
        slash_or_take_utxo.txout,
    ];
    let scripts = vec![vec![], vec![relative_timelock_script]];
    let taproot_spend_infos = vec![musig2_spend_info, slash_or_take_spend_info];
    TxHandler {
        tx,
        prevouts,
        scripts,
        taproot_spend_infos,
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
    use bitcoin::{hashes::Hash, Amount, OutPoint, Txid, XOnlyPublicKey};
    use secp256k1::{rand, Keypair, SecretKey};

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
            builder::script::anyone_can_spend_txout()
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
