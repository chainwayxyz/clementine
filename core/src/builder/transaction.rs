//! # Transaction Builder
//!
//! Transaction builder provides useful functions for building typical Bitcoin
//! transactions.

use super::address::create_taproot_address;
use crate::builder;
use crate::utils::SECP;
use crate::{utils, EVMAddress, UTXO};
use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::Hash;
use bitcoin::script::PushBytesBuf;
use bitcoin::{
    absolute, taproot::TaprootSpendInfo, Address, Amount, OutPoint, ScriptBuf, TxIn, TxOut, Witness,
};
use bitcoin::{Transaction, Txid};
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

    let timout_block_count_locked_script =
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
                &[timout_block_count_locked_script],
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

    let timout_block_count_locked_script =
        builder::script::generate_relative_timelock_script(operator_xonly_pk, timeout_block_count);

    let (timeout_input_addr, ttimeout_input_taproot_spend_info) = create_taproot_address(
        &[timout_block_count_locked_script.clone()],
        Some(operator_xonly_pk),
        network,
    );

    let prevouts = vec![TxOut {
        value: KICKOFF_INPUT_AMOUNT,
        script_pubkey: timeout_input_addr.script_pubkey(),
    }];
    let scripts = vec![vec![timout_block_count_locked_script]];
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

pub fn create_challenge_tx(
    kickoff_outpoint: OutPoint,
    operator_xonly_pk: XOnlyPublicKey,
) -> Transaction {
    let tx_ins = create_tx_ins(vec![kickoff_outpoint]);
    let tx_outs = create_tx_outs(vec![(
        Amount::from_int_btc(2),
        ScriptBuf::new_p2tr(&SECP, operator_xonly_pk, None),
    )]);

    create_btc_tx(tx_ins, tx_outs)
}

/// Creates a [`TxHandler`] for the watchtower challenge page transaction.
pub fn create_watchtower_challenge_page_txhandler(
    kickoff_utxo: &UTXO,
    nofn_xonly_pk: XOnlyPublicKey,
    bridge_amount_sats: Amount,
    num_watchtowers: u32,
    network: bitcoin::Network,
) -> TxHandler {
    let (nofn_musig2_address, _) = builder::address::create_musig2_address(nofn_xonly_pk, network);

    let tx_ins = create_tx_ins(vec![kickoff_utxo.outpoint]);

    // TODO: Txout values are dummy.
    let tx_outs = (0..num_watchtowers)
        .map(|_| TxOut {
            value: bridge_amount_sats - MOVE_TX_MIN_RELAY_FEE,
            script_pubkey: nofn_musig2_address.script_pubkey(),
        })
        .collect::<Vec<_>>();

    let wcptx = create_btc_tx(tx_ins, tx_outs);

    TxHandler {
        tx: wcptx,
        prevouts: vec![kickoff_utxo.txout.clone()],
        scripts: vec![vec![]],
        taproot_spend_infos: vec![],
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
    use crate::{builder, utils::SECP, UTXO};
    use bitcoin::{hashes::Hash, Amount, OutPoint, ScriptBuf, TxOut, Txid, XOnlyPublicKey};
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

    #[test]
    fn create_watchtower_challenge_page_txhandler() {
        let network = bitcoin::Network::Regtest;
        let secret_key = SecretKey::new(&mut rand::thread_rng());
        let nofn_xonly_pk =
            XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(&SECP, &secret_key)).0;
        let (nofn_musig2_address, _) =
            builder::address::create_musig2_address(nofn_xonly_pk, network);

        let kickoff_outpoint = OutPoint {
            txid: Txid::all_zeros(),
            vout: 0x45,
        };
        let kickoff_utxo = UTXO {
            outpoint: kickoff_outpoint,
            txout: TxOut {
                value: Amount::from_int_btc(2),
                script_pubkey: nofn_musig2_address.script_pubkey(),
            },
        };

        let bridge_amount_sats = Amount::from_sat(0x1F45);
        let num_watchtowers = 3;

        let wcp_txhandler = super::create_watchtower_challenge_page_txhandler(
            &kickoff_utxo,
            nofn_xonly_pk,
            bridge_amount_sats,
            num_watchtowers,
            network,
        );
        assert_eq!(wcp_txhandler.tx.output.len(), num_watchtowers as usize);
    }

    #[test]
    fn create_challenge_tx() {
        let operator_secret_key = SecretKey::new(&mut rand::thread_rng());
        let operator_xonly_pk =
            XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(&SECP, &operator_secret_key)).0;

        let kickoff_outpoint = OutPoint {
            txid: Txid::all_zeros(),
            vout: 0x45,
        };

        let challenge_tx = super::create_challenge_tx(kickoff_outpoint, operator_xonly_pk);
        assert_eq!(
            challenge_tx.tx_out(0).unwrap().value,
            Amount::from_int_btc(2)
        );
        assert_eq!(
            challenge_tx.tx_out(0).unwrap().script_pubkey,
            ScriptBuf::new_p2tr(&SECP, operator_xonly_pk, None)
        )
    }
}
