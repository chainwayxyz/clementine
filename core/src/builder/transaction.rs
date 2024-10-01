//! # Transaction Builder
//!
//! Transaction builder provides useful functions for building typical Bitcoin
//! transactions.

use crate::builder;
use crate::{utils, EVMAddress, UTXO};
use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::Hash;
use bitcoin::script::PushBytesBuf;
use bitcoin::Transaction;
use bitcoin::{
    absolute, taproot::TaprootSpendInfo, Address, Amount, OutPoint, ScriptBuf, TxIn, TxOut, Witness,
};
use secp256k1::XOnlyPublicKey;

#[derive(Debug, Clone)]
pub struct TxHandler {
    pub tx: bitcoin::Transaction,
    pub prevouts: Vec<TxOut>,
    pub scripts: Vec<Vec<ScriptBuf>>,
    pub taproot_spend_infos: Vec<TaprootSpendInfo>,
}

// TODO: Move these constants to the config file
pub const MOVE_TX_MIN_RELAY_FEE: u64 = 190;
pub const SLASH_OR_TAKE_TX_MIN_RELAY_FEE: u64 = 240;
pub const OPERATOR_TAKES_TX_MIN_RELAY_FEE: u64 = 230;
pub const KICKOFF_UTXO_AMOUNT_SATS: u64 = 100_000;

// Transaction Builders --------------------------------------------------------

/// Creates the move_tx to move the deposit.
pub fn create_move_tx(
    deposit_outpoint: OutPoint,
    nofn_xonly_pk: XOnlyPublicKey,
    bridge_amount_sats: u64,
    network: bitcoin::Network,
) -> Transaction {
    let (musig2_address, _) = builder::address::create_musig2_address(nofn_xonly_pk, network);

    let tx_ins = create_tx_ins(vec![deposit_outpoint]);

    let anyone_can_spend_txout = builder::script::anyone_can_spend_txout();
    let move_txout = TxOut {
        value: Amount::from_sat(bridge_amount_sats)
            - Amount::from_sat(MOVE_TX_MIN_RELAY_FEE)
            - anyone_can_spend_txout.value,
        script_pubkey: musig2_address.script_pubkey(),
    };

    create_btc_tx(tx_ins, vec![move_txout, anyone_can_spend_txout])
}

/// Creates an [`TxHandler`] that includes move_tx to move the deposit.
pub fn create_move_tx_handler(
    deposit_outpoint: OutPoint,
    evm_address: EVMAddress,
    recovery_taproot_address: &Address<NetworkUnchecked>,
    nofn_xonly_pk: XOnlyPublicKey,
    network: bitcoin::Network,
    user_takes_after: u32,
    bridge_amount_sats: u64,
) -> TxHandler {
    let move_tx = create_move_tx(deposit_outpoint, nofn_xonly_pk, bridge_amount_sats, network);

    let (deposit_address, deposit_taproot_spend_info) = builder::address::generate_deposit_address(
        nofn_xonly_pk,
        recovery_taproot_address,
        evm_address,
        bridge_amount_sats,
        network,
        user_takes_after,
    );

    let prevouts = vec![TxOut {
        script_pubkey: deposit_address.script_pubkey(),
        value: Amount::from_sat(bridge_amount_sats),
    }];

    let deposit_script = vec![builder::script::create_deposit_script(
        nofn_xonly_pk,
        evm_address,
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
        - Amount::from_sat(KICKOFF_UTXO_AMOUNT_SATS * num_kickoff_utxos_per_tx as u64)
        - builder::script::anyone_can_spend_txout().value
        - Amount::from_sat(kickoff_tx_min_relay_fee as u64);
    tracing::debug!("Change amount: {:?}", change_amount);
    let mut tx_outs_raw = vec![
        (
            Amount::from_sat(KICKOFF_UTXO_AMOUNT_SATS),
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

pub fn create_slash_or_take_tx(
    deposit_outpoint: OutPoint,
    kickoff_utxo: UTXO,
    operator_xonly_pk: XOnlyPublicKey,
    operator_idx: usize,
    nofn_xonly_pk: XOnlyPublicKey,
    network: bitcoin::Network,
    _user_takes_after: u32,
    operator_takes_after: u32,
    bridge_amount_sats: u64,
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
    let relative_timelock_script =
        builder::script::generate_relative_timelock_script(operator_xonly_pk, operator_takes_after);
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
            value: Amount::from_sat(
                kickoff_utxo.txout.value.to_sat() - 330 - SLASH_OR_TAKE_TX_MIN_RELAY_FEE,
            ),
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
    bridge_amount_sats: u64,
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

    let relative_timelock_script =
        builder::script::generate_relative_timelock_script(operator_xonly_pk, operator_takes_after);
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
            value: Amount::from_sat(slash_or_take_utxo.txout.value.to_sat())
                + Amount::from_sat(bridge_amount_sats)
                - Amount::from_sat(MOVE_TX_MIN_RELAY_FEE)
                - Amount::from_sat(OPERATOR_TAKES_TX_MIN_RELAY_FEE)
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
            value: Amount::from_sat(bridge_amount_sats)
                - Amount::from_sat(MOVE_TX_MIN_RELAY_FEE)
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

pub fn create_btc_tx(tx_ins: Vec<TxIn>, tx_outs: Vec<TxOut>) -> bitcoin::Transaction {
    bitcoin::Transaction {
        version: bitcoin::transaction::Version(2),
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
    use bitcoin::{hashes::Hash, OutPoint, Txid, XOnlyPublicKey};
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
        let bridge_amount_sats = 0x1F45;
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
}
