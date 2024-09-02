//! # Transaction Builder

use crate::{script_builder, utils, EVMAddress, UTXO};
use bitcoin::address::NetworkUnchecked;
use bitcoin::script::PushBytesBuf;
use bitcoin::Network;
use bitcoin::{
    absolute,
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, Amount, OutPoint, ScriptBuf, TxIn, TxOut, Witness,
};
use secp256k1::PublicKey;
use secp256k1::XOnlyPublicKey;

#[derive(Debug, Clone)]
pub struct TxHandler {
    pub tx: bitcoin::Transaction,
    pub prevouts: Vec<TxOut>,
    pub scripts: Vec<Vec<ScriptBuf>>,
    pub taproot_spend_infos: Vec<TaprootSpendInfo>,
}

pub type CreateAddressOutputs = (Address, TaprootSpendInfo);

#[derive(Debug, Clone)]
pub struct TransactionBuilder {
    _verifiers_xonly_pks: Vec<XOnlyPublicKey>,
    _verifiers_pks: Vec<PublicKey>,
    _network: Network,
}

// TODO: Move these constants to a config file
pub const MOVE_TX_MIN_RELAY_FEE: u64 = 305;
pub const SLASH_OR_TAKE_TX_MIN_RELAY_FEE: u64 = 305;
pub const WITHDRAWAL_TX_MIN_RELAY_FEE: u64 = 305;
pub const OPERATOR_TAKES_TX_MIN_RELAY_FEE: u64 = 305;
pub const KICKOFF_UTXO_AMOUNT_SATS: u64 = 100_000;

impl TransactionBuilder {
    /// Creates a new `TransactionBuilder`.
    pub fn new(verifiers_pks: Vec<PublicKey>, network: Network) -> Self {
        let verifiers_xonly_pks: Vec<XOnlyPublicKey> = verifiers_pks
            .iter()
            .map(|pk| PublicKey::x_only_public_key(pk).0)
            .collect();
        Self {
            _verifiers_xonly_pks: verifiers_xonly_pks,
            _verifiers_pks: verifiers_pks,
            _network: network,
        }
    }

    // ADDRESS BUILDERS

    pub fn create_taproot_address(
        scripts: &[ScriptBuf],
        internal_key: Option<XOnlyPublicKey>,
        network: bitcoin::Network,
    ) -> CreateAddressOutputs {
        let n = scripts.len();

        let taproot_builder = if n == 0 {
            TaprootBuilder::new()
        } else if n > 1 {
            let m: u8 = ((n - 1).ilog2() + 1) as u8; // m = ceil(log(n))
            let k = 2_usize.pow(m.into()) - n;
            (0..n).fold(TaprootBuilder::new(), |acc, i| {
                acc.add_leaf(m - ((i >= n - k) as u8), scripts[i].clone())
                    .unwrap()
            })
        } else {
            TaprootBuilder::new()
                .add_leaf(0, scripts[0].clone())
                .unwrap()
        };

        let tree_info = match internal_key {
            Some(xonly_pk) => taproot_builder.finalize(&utils::SECP, xonly_pk).unwrap(),
            None => taproot_builder
                .finalize(&utils::SECP, *utils::UNSPENDABLE_XONLY_PUBKEY)
                .unwrap(),
        };

        let taproot_address = match internal_key {
            Some(xonly_pk) => {
                Address::p2tr(&utils::SECP, xonly_pk, tree_info.merkle_root(), network)
            }
            None => Address::p2tr(
                &utils::SECP,
                *utils::UNSPENDABLE_XONLY_PUBKEY,
                tree_info.merkle_root(),
                network,
            ),
        };

        (taproot_address, tree_info)
    }

    /// Generates a deposit address for the user. N-of-N or user takes after
    /// timelock script can be used to spend the funds.
    pub fn generate_deposit_address(
        nofn_xonly_pk: &XOnlyPublicKey,
        recovery_taproot_address: &Address<NetworkUnchecked>,
        user_evm_address: &EVMAddress,
        amount: u64,
        network: bitcoin::Network,
        user_takes_after: u32,
    ) -> CreateAddressOutputs {
        let deposit_script =
            script_builder::create_deposit_script(nofn_xonly_pk, user_evm_address, amount);

        let recovery_script_pubkey = recovery_taproot_address
            .clone()
            .assume_checked()
            .script_pubkey();
        let recovery_extracted_xonly_pk =
            XOnlyPublicKey::from_slice(&recovery_script_pubkey.as_bytes()[2..34]).unwrap();

        let script_timelock = script_builder::generate_relative_timelock_script(
            &recovery_extracted_xonly_pk,
            user_takes_after,
        );

        TransactionBuilder::create_taproot_address(
            &[deposit_script, script_timelock],
            None,
            network,
        )
    }

    pub fn create_musig2_address(
        nofn_xonly_pk: XOnlyPublicKey,
        network: bitcoin::Network,
    ) -> CreateAddressOutputs {
        TransactionBuilder::create_taproot_address(&[], Some(nofn_xonly_pk), network)
    }

    pub fn create_kickoff_address(
        nofn_xonly_pk: &XOnlyPublicKey,
        operator_xonly_pk: &XOnlyPublicKey,
        network: bitcoin::Network,
    ) -> CreateAddressOutputs {
        let musig2_and_operator_script = script_builder::create_musig2_and_operator_multisig_script(
            nofn_xonly_pk,
            operator_xonly_pk,
        );
        TransactionBuilder::create_taproot_address(&[musig2_and_operator_script], None, network)
    }

    // TX BUILDERS

    /// Creates the move_tx to move the deposit.
    pub fn create_move_tx(
        deposit_outpoint: OutPoint,
        evm_address: &EVMAddress,
        recovery_taproot_address: &Address<NetworkUnchecked>,
        nofn_xonly_pk: &XOnlyPublicKey,
        network: bitcoin::Network,
        user_takes_after: u32,
        bridge_amount_sats: u64,
    ) -> TxHandler {
        let anyone_can_spend_txout = script_builder::anyone_can_spend_txout();
        let (musig2_address, _) = Self::create_musig2_address(*nofn_xonly_pk, network);
        let (deposit_address, deposit_taproot_spend_info) =
            TransactionBuilder::generate_deposit_address(
                nofn_xonly_pk,
                recovery_taproot_address,
                evm_address,
                bridge_amount_sats,
                network,
                user_takes_after,
            );
        let move_txout = TxOut {
            value: Amount::from_sat(bridge_amount_sats)
                - Amount::from_sat(MOVE_TX_MIN_RELAY_FEE)
                - anyone_can_spend_txout.value,
            script_pubkey: musig2_address.script_pubkey(),
        };
        let tx_ins = TransactionBuilder::create_tx_ins(vec![deposit_outpoint]);
        let move_tx =
            TransactionBuilder::create_btc_tx(tx_ins, vec![move_txout, anyone_can_spend_txout]);
        let prevouts = vec![TxOut {
            script_pubkey: deposit_address.script_pubkey(),
            value: Amount::from_sat(bridge_amount_sats),
        }];
        let deposit_script = vec![script_builder::create_deposit_script(
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
        nofn_xonly_pk: &XOnlyPublicKey,
        operator_xonly_pk: &XOnlyPublicKey,
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
        let tx_ins = TransactionBuilder::create_tx_ins(vec![funding_utxo.outpoint]);
        let musig2_and_operator_script = script_builder::create_musig2_and_operator_multisig_script(
            nofn_xonly_pk,
            operator_xonly_pk,
        );
        let (musig2_and_operator_address, _) = TransactionBuilder::create_taproot_address(
            &[musig2_and_operator_script],
            None,
            network,
        );
        let operator_address = Address::p2tr(&utils::SECP, *operator_xonly_pk, None, network);
        let change_amount = funding_utxo.txout.value
            - Amount::from_sat(KICKOFF_UTXO_AMOUNT_SATS * num_kickoff_utxos_per_tx as u64)
            - script_builder::anyone_can_spend_txout().value
            - Amount::from_sat(kickoff_tx_min_relay_fee as u64);

        let mut tx_outs_raw = vec![
            (
                Amount::from_sat(KICKOFF_UTXO_AMOUNT_SATS),
                musig2_and_operator_address.script_pubkey(),
            );
            num_kickoff_utxos_per_tx
        ];

        tx_outs_raw.push((change_amount, operator_address.script_pubkey()));
        tx_outs_raw.push((
            script_builder::anyone_can_spend_txout().value,
            script_builder::anyone_can_spend_txout().script_pubkey,
        ));
        let tx_outs = TransactionBuilder::create_tx_outs(tx_outs_raw);
        let tx = TransactionBuilder::create_btc_tx(tx_ins, tx_outs);
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
        operator_xonly_pk: &XOnlyPublicKey,
        operator_idx: usize,
        nofn_xonly_pk: &XOnlyPublicKey,
        network: bitcoin::Network,
        user_takes_after: u32,
        operator_takes_after: u32,
        bridge_amount_sats: u64,
    ) -> TxHandler {
        // First recreate the move_tx and move_txid. We can give dummy values for some of the parameters since we are only interested in txid.
        let move_tx_handler = TransactionBuilder::create_move_tx(
            deposit_outpoint,
            &EVMAddress([0u8; 20]),
            Address::p2tr(
                &utils::SECP,
                *utils::UNSPENDABLE_XONLY_PUBKEY,
                None,
                network,
            )
            .as_unchecked(),
            nofn_xonly_pk,
            network,
            user_takes_after,
            bridge_amount_sats,
        );
        let move_txid = move_tx_handler.tx.compute_txid();

        let (kickoff_utxo_address, kickoff_utxo_spend_info) =
            Self::create_kickoff_address(nofn_xonly_pk, operator_xonly_pk, network);
        // tracing::debug!(
        //     "kickoff_utxo_script_pubkey: {:?}",
        //     kickoff_utxo_address.script_pubkey()
        // );
        // tracing::debug!("kickoff_utxo_spend_info: {:?}", kickoff_utxo_spend_info);
        // tracing::debug!("kickoff_utxooo: {:?}", kickoff_utxo);
        let musig2_and_operator_script = script_builder::create_musig2_and_operator_multisig_script(
            nofn_xonly_pk,
            operator_xonly_pk,
        );
        // Sanity check
        assert!(kickoff_utxo_address.script_pubkey() == kickoff_utxo.txout.script_pubkey);
        let ins = Self::create_tx_ins(vec![kickoff_utxo.outpoint]);
        let relative_timelock_script = script_builder::generate_relative_timelock_script(
            operator_xonly_pk,
            operator_takes_after,
        );
        let (slash_or_take_address, _) = TransactionBuilder::create_taproot_address(
            &[relative_timelock_script.clone()],
            Some(*nofn_xonly_pk),
            network,
        );
        let mut op_return_script: Vec<u8> = hex::decode(move_txid.to_string()).unwrap();
        op_return_script.extend(utils::usize_to_var_len_bytes(operator_idx));
        let mut push_bytes = PushBytesBuf::new();
        push_bytes.extend_from_slice(&op_return_script).unwrap();
        let op_return_txout = script_builder::op_return_txout(push_bytes);
        let outs = vec![
            TxOut {
                value: Amount::from_sat(
                    kickoff_utxo.txout.value.to_sat() - 330 - SLASH_OR_TAKE_TX_MIN_RELAY_FEE,
                ),
                script_pubkey: slash_or_take_address.script_pubkey(),
            },
            script_builder::anyone_can_spend_txout(),
            op_return_txout,
        ];
        let tx = TransactionBuilder::create_btc_tx(ins, outs);
        let prevouts = vec![kickoff_utxo.txout.clone()];
        let scripts = vec![vec![musig2_and_operator_script]];
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
        operator_xonly_pk: &XOnlyPublicKey,
        nofn_xonly_pk: &XOnlyPublicKey,
        network: bitcoin::Network,
        operator_takes_after: u32,
        bridge_amount_sats: u64,
    ) -> TxHandler {
        let operator_address = Address::p2tr(&utils::SECP, *operator_xonly_pk, None, network);
        let mut ins = TransactionBuilder::create_tx_ins(vec![bridge_fund_outpoint]);
        ins.extend(TransactionBuilder::create_tx_ins_with_sequence(
            vec![slash_or_take_utxo.outpoint],
            operator_takes_after as u16,
        ));

        let (musig2_address, musig2_spend_info) =
            TransactionBuilder::create_musig2_address(*nofn_xonly_pk, network);

        let relative_timelock_script = script_builder::generate_relative_timelock_script(
            operator_xonly_pk,
            operator_takes_after,
        );
        let (slash_or_take_address, slash_or_take_spend_info) =
            TransactionBuilder::create_taproot_address(
                &[relative_timelock_script.clone()],
                Some(*nofn_xonly_pk),
                network,
            );

        // Sanity check
        assert!(slash_or_take_address.script_pubkey() == slash_or_take_utxo.txout.script_pubkey);

        let outs = vec![
            TxOut {
                value: Amount::from_sat(slash_or_take_utxo.txout.value.to_sat())
                    + Amount::from_sat(bridge_amount_sats)
                    - Amount::from_sat(MOVE_TX_MIN_RELAY_FEE)
                    - Amount::from_sat(OPERATOR_TAKES_TX_MIN_RELAY_FEE)
                    - script_builder::anyone_can_spend_txout().value
                    - script_builder::anyone_can_spend_txout().value,
                script_pubkey: operator_address.script_pubkey(),
            },
            script_builder::anyone_can_spend_txout(),
        ];
        let tx = TransactionBuilder::create_btc_tx(ins, outs);
        let prevouts = vec![
            TxOut {
                script_pubkey: musig2_address.script_pubkey(),
                value: Amount::from_sat(bridge_amount_sats)
                    - Amount::from_sat(MOVE_TX_MIN_RELAY_FEE)
                    - script_builder::anyone_can_spend_txout().value,
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
}

// #[cfg(test)]
// mod tests {

//     use bitcoin::{Address, XOnlyPublicKey};
//     use secp256k1::PublicKey;

//     use crate::{config::BridgeConfig, transaction_builder::TransactionBuilder};
//     use std::str::FromStr;

//     #[test]
//     fn deposit_address() {
//         let config = BridgeConfig::new();

//         let secp = secp256k1::Secp256k1::new();

//         let verifier_pks_hex: Vec<&str> = vec![
//             "029bef8d556d80e43ae7e0becb3a7e6838b95defe45896ed6075bb9035d06c9964",
//             "02e37d58a1aae4ba059fd2503712d998470d3a2522f7e2335f544ef384d2199e02",
//             "02688466442a134ee312299bafb37058e385c98dd6005eaaf0f538f533efe5f91f",
//             "02337cca2171fdbfcfd657fa59881f46269f1e590b5ffab6023686c7ad2ecc2c1c",
//             "02a1f9821c983cfe80558fb0b56385c67c8df6824c17aed048c7cbd031549a2fa8",
//         ];
//         let verifier_pks: Vec<PublicKey> = verifier_pks_hex
//             .iter()
//             .map(|pk| PublicKey::from_str(pk).unwrap())
//             .collect();

//         let tx_builder = TransactionBuilder::new(verifier_pks, config.network);

//         let evm_address: [u8; 20] = hex::decode("1234567890123456789012345678901234567890")
//             .unwrap()
//             .try_into()
//             .unwrap();

//         let user_xonly_pk: XOnlyPublicKey = XOnlyPublicKey::from_str(
//             "93c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51",
//         )
//         .unwrap();

//         let recovery_taproot_address =
//             Address::p2tr(&secp, user_xonly_pk, None, bitcoin::Network::Regtest);

//         let deposit_address = TransactionBuilder::generate_deposit_address(
//             &user_xonly_pk,
//             recovery_taproot_address.as_unchecked(),
//             &crate::EVMAddress(evm_address),
//             10_000,
//             200,
//             bitcoin::Network::Regtest,
//         );
//         println!("deposit_address: {:?}", deposit_address.0);

//         assert_eq!(
//             deposit_address.0.to_string(),
//             "bcrt1prqxsjz7h5wt40w54vhmpvn6l2hu8mefmez6ld4p59vksllumskvqs8wvkh" // check this later
//         ) // Comparing it to the taproot address generated in bridge backend repo (using js)
//     }
// }
